# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Emit outbound webhook events from gateway decisions (v1.3.0).

The scan-request hot path calls `emit_from_audit_background` via FastAPI
BackgroundTasks so that ALL webhook work -- endpoint lookup, payload
build, per-endpoint XADD -- runs AFTER the HTTP response body is on the
wire. The scan response never blocks on webhook subsystem I/O.

Payload body is a whitelisted projection of the SAME dict passed to
AuditRepository.create at the call site, so the wire shape matches
GET /v1/audit/logs -- a customer's SIEM sees identical schema on both
channels without a translation layer.

Design constraints:

  * Never raise into the caller. Every failure mode below is
    log-and-swallow, and the DB read is bounded by the single
    ix_webhook_endpoints_tenant_disabled index seek.

  * Fire-and-forget. The emit performs one endpoint lookup and one
    XADD per subscribed endpoint, then returns. Actual HTTP delivery,
    retries, and DLQ handling happen in workers/webhook_delivery.py.

Event taxonomy (v1.3.0):

    wrapsec.request.blocked    - decision == BLOCK
    wrapsec.request.sanitized  - decision == SANITIZE

ALLOW is deliberately NOT emitted -- it is 95%+ of traffic for a healthy
tenant and would drown the delivery pipeline in low-value fanout.
"""

from __future__ import annotations
from services.time import to_iso_z, utc_now

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from cache import webhook_queue
from cache.redis_client import get_redis
from db.repositories.webhook_endpoint import WebhookEndpointRepository
from db.session import AsyncSessionFactory
from domain.value_objects.severity import compute_severity

logger = logging.getLogger("wrapsec.webhook_emitter")


EVENT_BLOCKED   = "wrapsec.request.blocked"
EVENT_SANITIZED = "wrapsec.request.sanitized"


# Fields projected from the audit dict into the webhook body. Matches the
# shape returned by GET /v1/audit/logs (_format_item in api/v1/endpoints/
# audit.py) so a customer's SIEM sees the same schema in both channels.
#
# Deliberately excluded, even if present in the dict:
#   * record_hash / prev_hash  - internal hash-chain columns; never leave
#                                the database, no external consumer use.
#   * proxy_interaction_id     - internal FK; join in DB, not over the wire.
#   * attribution_verified     - internal flag; not user-facing yet.
_ALLOWED_AUDIT_FIELDS = frozenset({
    "trace_id",
    "tenant_id",
    "decision",
    "primary_reason",
    "risk_score",
    "confidence",
    "confidence_band",
    "threats",
    "input_hash",
    "detection_mode",
    "execution_mode",
    "latency_ms",
    "key_id",
    "dept_id",
    "app_id",
    "user_id",
    "source",
    "ip_address",
    "policy_source",
    "input_length",
    "severity",
    "session_id",
    "turn_index",
    "run_id",
})


def _event_type_for_decision(decision: str) -> str | None:
    """Return the wire event name for a decision, or None if we do not emit."""
    if decision == "BLOCK":
        return EVENT_BLOCKED
    if decision == "SANITIZE":
        return EVENT_SANITIZED
    return None


def _build_body(audit_data: dict[str, Any]) -> dict[str, Any]:
    """
    Project the audit-log dict into the webhook body.

    Whitelist copy so a new column added to the audit dict cannot silently
    leak over the wire; also stringifies UUIDs (JSON-safe) and adds a
    `timestamp` field mirroring what audit_logs receive at DB-write time
    (the emitter fires immediately after that write, so wall time is a
    correct-enough proxy for the row's created_at).
    """
    body: dict[str, Any] = {"timestamp": to_iso_z(utc_now())}
    for key in _ALLOWED_AUDIT_FIELDS:
        if key not in audit_data:
            continue
        value = audit_data[key]
        if isinstance(value, UUID):
            value = str(value)
        body[key] = value

    # Severity may be absent from the caller's dict on older code paths;
    # backfill using the canonical taxonomy so downstream consumers can
    # always trust body.severity to be present.
    if "severity" not in body:
        body["severity"] = compute_severity(
            decision       = str(audit_data.get("decision", "")),
            risk_score     = float(audit_data.get("risk_score") or 0.0),
            primary_reason = audit_data.get("primary_reason"),
        )
    return body


async def emit_from_audit(
    db:         AsyncSession,
    redis:      Redis,
    audit_data: dict[str, Any],
) -> int:
    """
    Enqueue an outbound webhook for every enabled endpoint on the tenant
    that subscribes to the event type derived from `audit_data["decision"]`.

    `audit_data` is the SAME dict passed to AuditRepository.create at the
    same call site -- the emitter projects a whitelisted subset into the
    payload body so the wire shape stays a faithful subset of the audit
    row that was just persisted.

    Returns the number of endpoints enqueued (0 if decision is ALLOW, no
    tenant is attributed, no endpoint subscribes, or an error is swallowed).
    NEVER raises to the caller -- callers on the scan response path must
    be immune to webhook subsystem failures.
    """
    decision = str(audit_data.get("decision") or "")
    event_type = _event_type_for_decision(decision)
    if event_type is None:
        return 0

    tenant_id = audit_data.get("tenant_id")
    if tenant_id is None:
        return 0

    tenant_str  = str(tenant_id)
    trace_id    = str(audit_data.get("trace_id") or "")

    try:
        repo      = WebhookEndpointRepository(db)
        endpoints = await repo.find_active_for_event(
            tenant_id  = tenant_id if isinstance(tenant_id, UUID) else UUID(tenant_str),
            event_type = event_type,
        )
    except Exception as exc:                              # noqa: BLE001
        logger.exception("webhook_endpoints lookup failed trace_id=%s: %s", trace_id, exc)
        return 0

    if not endpoints:
        return 0

    body = _build_body(audit_data)

    enqueued = 0
    for ep in endpoints:
        payload = {
            "endpoint_id":    str(ep.id),
            "tenant_id":      tenant_str,
            # Stable message id so retries and receiver-side dedup treat every
            # delivery attempt of this event as the same logical message. Fits
            # the audit-log msg_id column (String(64)); UUID trace_id is 36c.
            "msg_id":         trace_id,
            "event_type":     event_type,
            "attempt_number": 1,
            "body":           body,
        }
        try:
            await webhook_queue.enqueue(redis, payload)
            enqueued += 1
        except Exception as exc:                          # noqa: BLE001
            logger.exception(
                "webhook enqueue failed endpoint_id=%s trace_id=%s: %s",
                ep.id, trace_id, exc,
            )

    logger.debug(
        "webhook emit trace_id=%s event=%s tenant=%s endpoints=%d",
        trace_id, event_type, tenant_str, enqueued,
    )
    return enqueued


async def emit_from_audit_background(audit_data: dict[str, Any]) -> None:
    """
    FastAPI BackgroundTasks entry point.

    Runs AFTER the response body has been sent, so the DB lookup and
    per-endpoint XADD costs never appear on scan tail latency. Owns its
    own session and Redis handle because the request-scoped `db` is
    already closed by the time this fires.

    Never raises -- the response is already gone, and any exception here
    would only pollute logs without changing user-visible behavior.
    """
    try:
        async with AsyncSessionFactory() as db:
            await emit_from_audit(db=db, redis=get_redis(), audit_data=audit_data)
    except Exception as exc:                              # noqa: BLE001
        logger.exception(
            "webhook background emit failed trace_id=%s: %s",
            audit_data.get("trace_id"), exc,
        )
