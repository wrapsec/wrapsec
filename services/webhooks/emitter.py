# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Emit outbound webhook events from gateway decisions (v1.3.0).

Public entry point: `emit_gateway_decision`. Called from the scan endpoint
after the audit_log write, once per request whose decision is BLOCK or
SANITIZE. ALLOW decisions are intentionally NOT emitted -- for a real
tenant this is 95%+ of traffic and would drown the delivery pipeline in
low-value fanout.

Design constraints:

  * The emit call MUST NOT block or fail the scan response. Every failure
    mode below is log-and-swallow, and the DB read is bounded by the
    single ix_webhook_endpoints_tenant_disabled index seek.

  * The emit is fire-and-forget from the request path. It performs one
    endpoint lookup and one XADD per subscribed endpoint, then returns.
    Actual HTTP delivery, retries, and DLQ handling happen in the
    background worker started in commit #4.

  * severity + primary_reason + threats are taken from the already-computed
    domain values -- webhook payloads consume the canonical audit-log
    fields verbatim so downstream tooling never sees a divergent taxonomy.

Event taxonomy (v1.3.0):

    wrapsec.request.blocked    - decision == BLOCK
    wrapsec.request.sanitized  - decision == SANITIZE

New event types (endpoint-failure, circuit-breaker-tripped, etc.) land in
later v1.3.0 commits and reuse the same envelope.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from cache import webhook_queue
from db.repositories.webhook_endpoint import WebhookEndpointRepository
from domain.value_objects.severity import compute_severity

logger = logging.getLogger("wrapsec.webhook_emitter")


EVENT_BLOCKED   = "wrapsec.request.blocked"
EVENT_SANITIZED = "wrapsec.request.sanitized"


def _event_type_for_decision(decision: str) -> str | None:
    """Return the wire event name for a decision, or None if we do not emit."""
    if decision == "BLOCK":
        return EVENT_BLOCKED
    if decision == "SANITIZE":
        return EVENT_SANITIZED
    return None


def _build_event_body(
    trace_id:       str,
    tenant_id:      str,
    decision:       str,
    risk_score:     float,
    primary_reason: str | None,
    confidence:     float | None,
    threats:        list[str],
    severity:       str,
    source:         str | None,
    user_id:        str | None,
    detection_mode: str | None,
    execution_mode: str | None,
) -> dict[str, Any]:
    """
    Envelope emitted inside the queue payload's `body` field.

    Fields deliberately mirror audit_logs so downstream SIEM pipelines can
    join on trace_id without a schema translation step. Sanitized/original
    input text is NOT included -- payloads may leave the tenant boundary,
    and PII redaction ran on the input path but not on threat context.
    """
    return {
        "trace_id":       trace_id,
        "tenant_id":      tenant_id,
        "occurred_at":    datetime.utcnow().isoformat() + "Z",
        "decision":       decision,
        "severity":       severity,
        "risk_score":     risk_score,
        "primary_reason": primary_reason,
        "confidence":     confidence,
        "threats":        threats,
        "source":         source,
        "user_id":        user_id,
        "detection_mode": detection_mode,
        "execution_mode": execution_mode,
    }


async def emit_gateway_decision(
    db:             AsyncSession,
    redis:          Redis,
    tenant_id:      UUID | str | None,
    trace_id:       str,
    decision:       str,
    risk_score:     float,
    primary_reason: str | None,
    confidence:     float | None,
    threats:        list[str],
    source:         str | None       = None,
    user_id:        str | None       = None,
    detection_mode: str | None       = None,
    execution_mode: str | None       = None,
) -> int:
    """
    Enqueue an outbound webhook for every enabled endpoint on `tenant_id`
    that subscribes to the derived event type.

    Returns the number of endpoints enqueued (0 if the decision is ALLOW,
    the tenant has no matching endpoints, or an error was swallowed).
    NEVER raises to the caller -- the scan response path must be immune to
    webhook subsystem failures.
    """
    event_type = _event_type_for_decision(decision)
    if event_type is None:
        return 0

    if tenant_id is None:
        # System-level or test requests without a tenant have no destination
        # to route to; nothing to do.
        return 0

    tenant_str = str(tenant_id)

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

    severity = compute_severity(
        decision       = decision,
        risk_score     = risk_score,
        primary_reason = primary_reason,
    )
    body = _build_event_body(
        trace_id       = trace_id,
        tenant_id      = tenant_str,
        decision       = decision,
        risk_score     = risk_score,
        primary_reason = primary_reason,
        confidence     = confidence,
        threats        = threats,
        severity       = severity,
        source         = source,
        user_id        = user_id,
        detection_mode = detection_mode,
        execution_mode = execution_mode,
    )

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
            # Never fail the scan response for a webhook queue error. The
            # miss is loud in the logs; a future v1.3.x add-on may fall back
            # to a durable outbox table if this proves lossy in the field.
            logger.exception(
                "webhook enqueue failed endpoint_id=%s trace_id=%s: %s",
                ep.id, trace_id, exc,
            )

    logger.debug(
        "webhook emit trace_id=%s event=%s tenant=%s endpoints=%d",
        trace_id, event_type, tenant_str, enqueued,
    )
    return enqueued
