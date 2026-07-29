# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.emitter.

The emitter sits on the scan-request hot path. These tests pin the invariants
that keep it safe to call from that path:

  1. ALLOW decisions never touch Redis (silence for the 95% common case).
  2. Requests without a tenant_id never touch Redis (system/test paths).
  3. BLOCK enqueues on subscribed endpoints with the canonical taxonomy.
  4. SANITIZE enqueues on subscribed endpoints with the correct event type.
  5. Payload body is a whitelisted projection of the audit_logs field set
     (never includes hash-chain columns; UUIDs are stringified).
  6. Missing severity in the audit dict is backfilled via compute_severity.
  7. Errors in the DB lookup or the enqueue are swallowed -- the emitter
     is never allowed to raise into the caller.
"""

from __future__ import annotations

from uuid import UUID, uuid4
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.webhooks import emitter
from services.webhooks.emitter import (
    EVENT_BLOCKED,
    EVENT_SANITIZED,
    _event_type_for_decision,
    emit_from_audit,
)


def _endpoint():
    ep = MagicMock()
    ep.id          = uuid4()
    ep.tenant_id   = uuid4()
    ep.event_types = None
    ep.disabled    = False
    return ep


def _audit(**overrides):
    """A minimal audit dict shaped like the one AuditRepository.create
    receives from api/v1/endpoints/ai.py at the same call site as the emit."""
    base = {
        "trace_id":         "trace-abc",
        "tenant_id":        uuid4(),
        "decision":         "BLOCK",
        "risk_score":       0.95,
        "primary_reason":   "RULE_DETECTOR",
        "confidence":       0.9,
        "confidence_band":  "HIGH",
        "threats":          ["prompt_injection"],
        "input_hash":       "sha256:deadbeef",
        "detection_mode":   "fast",
        "execution_mode":   "scan_only",
        "latency_ms":       12.5,
        "source":           "api",
        "user_id":          "u1",
        "severity":         "CRITICAL",
    }
    base.update(overrides)
    return base


# ─── _event_type_for_decision ────────────────────────────────────────────

def test_event_type_for_block():
    assert _event_type_for_decision("BLOCK") == EVENT_BLOCKED


def test_event_type_for_sanitize():
    assert _event_type_for_decision("SANITIZE") == EVENT_SANITIZED


def test_event_type_for_allow_is_none():
    """ALLOW must not emit -- volume would drown the delivery pipeline."""
    assert _event_type_for_decision("ALLOW") is None


# ─── emit_from_audit: no-emit paths ──────────────────────────────────────

@pytest.mark.asyncio
async def test_allow_decision_never_calls_repo_or_enqueue():
    db    = MagicMock()
    redis = AsyncMock()

    with patch.object(emitter, "WebhookEndpointRepository") as Repo, \
         patch.object(emitter.webhook_queue, "enqueue", new=AsyncMock()) as enq:

        n = await emit_from_audit(db=db, redis=redis, audit_data=_audit(decision="ALLOW"))

        assert n == 0
        Repo.assert_not_called()
        enq.assert_not_called()


@pytest.mark.asyncio
async def test_missing_tenant_never_calls_repo_or_enqueue():
    db    = MagicMock()
    redis = AsyncMock()

    with patch.object(emitter, "WebhookEndpointRepository") as Repo, \
         patch.object(emitter.webhook_queue, "enqueue", new=AsyncMock()) as enq:

        n = await emit_from_audit(db=db, redis=redis, audit_data=_audit(tenant_id=None))

        assert n == 0
        Repo.assert_not_called()
        enq.assert_not_called()


@pytest.mark.asyncio
async def test_no_subscribed_endpoints_returns_zero_and_does_not_enqueue():
    db    = MagicMock()
    redis = AsyncMock()
    tenant = uuid4()

    repo_instance = MagicMock()
    repo_instance.find_active_for_event = AsyncMock(return_value=[])

    with patch.object(emitter, "WebhookEndpointRepository", return_value=repo_instance), \
         patch.object(emitter.webhook_queue, "enqueue", new=AsyncMock()) as enq:

        n = await emit_from_audit(db=db, redis=redis, audit_data=_audit(tenant_id=tenant))

        assert n == 0
        enq.assert_not_called()
        repo_instance.find_active_for_event.assert_awaited_once()
        call = repo_instance.find_active_for_event.await_args
        assert call.kwargs["tenant_id"] == tenant
        assert call.kwargs["event_type"] == EVENT_BLOCKED


# ─── emit_from_audit: enqueue paths ──────────────────────────────────────

@pytest.mark.asyncio
async def test_block_enqueues_one_payload_per_endpoint_with_audit_shape():
    """Body must be a projection of the audit dict, not a hand-picked set."""
    db     = MagicMock()
    redis  = AsyncMock()
    tenant = uuid4()

    eps = [_endpoint(), _endpoint(), _endpoint()]
    repo_instance = MagicMock()
    repo_instance.find_active_for_event = AsyncMock(return_value=eps)

    captured = []

    async def fake_enqueue(r, payload):
        captured.append(payload)
        return "1-0"

    audit_data = _audit(tenant_id=tenant)

    with patch.object(emitter, "WebhookEndpointRepository", return_value=repo_instance), \
         patch.object(emitter.webhook_queue, "enqueue", new=fake_enqueue):

        n = await emit_from_audit(db=db, redis=redis, audit_data=audit_data)

        assert n == 3
        assert len(captured) == 3

        for p, ep in zip(captured, eps):
            assert p["event_type"]     == EVENT_BLOCKED
            assert p["endpoint_id"]    == str(ep.id)
            assert p["tenant_id"]      == str(tenant)
            assert p["msg_id"]         == "trace-abc"
            assert p["attempt_number"] == 1

            body = p["body"]
            # Fields projected verbatim from the audit dict.
            assert body["trace_id"]        == "trace-abc"
            assert body["decision"]        == "BLOCK"
            assert body["risk_score"]      == 0.95
            assert body["primary_reason"]  == "RULE_DETECTOR"
            assert body["confidence"]      == 0.9
            assert body["confidence_band"] == "HIGH"
            assert body["threats"]         == ["prompt_injection"]
            assert body["input_hash"]      == "sha256:deadbeef"
            assert body["detection_mode"]  == "fast"
            assert body["execution_mode"]  == "scan_only"
            assert body["latency_ms"]      == 12.5
            assert body["source"]          == "api"
            assert body["user_id"]         == "u1"
            assert body["severity"]        == "CRITICAL"
            # tenant_id is stringified so JSON serialization does not choke on UUID.
            assert body["tenant_id"]       == str(tenant)
            # Timestamp is added by the emitter (audit_data lacks it before DB write).
            assert "timestamp" in body


@pytest.mark.asyncio
async def test_sanitize_enqueues_with_sanitized_event_type():
    db     = MagicMock()
    redis  = AsyncMock()
    tenant = uuid4()

    ep = _endpoint()
    repo_instance = MagicMock()
    repo_instance.find_active_for_event = AsyncMock(return_value=[ep])

    captured = {}

    async def fake_enqueue(r, payload):
        captured.update(payload)
        return "1-0"

    with patch.object(emitter, "WebhookEndpointRepository", return_value=repo_instance), \
         patch.object(emitter.webhook_queue, "enqueue", new=fake_enqueue):

        n = await emit_from_audit(
            db=db, redis=redis,
            audit_data=_audit(
                tenant_id=tenant,
                decision="SANITIZE",
                risk_score=0.5,
                primary_reason="PII_GUARDRAIL_SANITIZE",
                severity="MEDIUM",
            ),
        )

        assert n == 1
        assert captured["event_type"] == EVENT_SANITIZED
        assert captured["body"]["severity"] == "MEDIUM"
        assert repo_instance.find_active_for_event.await_args.kwargs["event_type"] == EVENT_SANITIZED


@pytest.mark.asyncio
async def test_missing_severity_is_backfilled_via_compute_severity():
    """Older code paths may pass audit dicts without severity precomputed;
    the emitter must always publish a severity field so consumers can trust it."""
    db     = MagicMock()
    redis  = AsyncMock()
    tenant = uuid4()

    ep = _endpoint()
    repo_instance = MagicMock()
    repo_instance.find_active_for_event = AsyncMock(return_value=[ep])

    captured = {}

    async def fake_enqueue(r, payload):
        captured.update(payload)
        return "1-0"

    audit_data = _audit(tenant_id=tenant)
    del audit_data["severity"]

    with patch.object(emitter, "WebhookEndpointRepository", return_value=repo_instance), \
         patch.object(emitter.webhook_queue, "enqueue", new=fake_enqueue):

        await emit_from_audit(db=db, redis=redis, audit_data=audit_data)

        # BLOCK with risk_score 0.95 -> CRITICAL per the canonical taxonomy.
        assert captured["body"]["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_body_excludes_hash_chain_columns_even_if_present():
    """record_hash / prev_hash are internal integrity columns; the whitelist
    must drop them so they never leave the tenant boundary over the wire."""
    db     = MagicMock()
    redis  = AsyncMock()
    tenant = uuid4()

    ep = _endpoint()
    repo_instance = MagicMock()
    repo_instance.find_active_for_event = AsyncMock(return_value=[ep])

    captured = {}

    async def fake_enqueue(r, payload):
        captured.update(payload)
        return "1-0"

    audit_data = _audit(
        tenant_id=tenant,
        record_hash="chain-hash-abc",
        prev_hash="chain-hash-prev",
        proxy_interaction_id=uuid4(),
        attribution_verified=True,
    )

    with patch.object(emitter, "WebhookEndpointRepository", return_value=repo_instance), \
         patch.object(emitter.webhook_queue, "enqueue", new=fake_enqueue):

        await emit_from_audit(db=db, redis=redis, audit_data=audit_data)

        body = captured["body"]
        assert "record_hash" not in body
        assert "prev_hash"   not in body
        assert "proxy_interaction_id" not in body
        assert "attribution_verified" not in body


# ─── emit_from_audit: failure isolation ──────────────────────────────────

@pytest.mark.asyncio
async def test_repo_failure_is_swallowed_and_returns_zero():
    """Scan responses must never fail because the webhook lookup did."""
    db    = MagicMock()
    redis = AsyncMock()

    repo_instance = MagicMock()
    repo_instance.find_active_for_event = AsyncMock(side_effect=RuntimeError("DB down"))

    with patch.object(emitter, "WebhookEndpointRepository", return_value=repo_instance), \
         patch.object(emitter.webhook_queue, "enqueue", new=AsyncMock()) as enq:

        n = await emit_from_audit(db=db, redis=redis, audit_data=_audit())

        assert n == 0
        enq.assert_not_called()


@pytest.mark.asyncio
async def test_enqueue_failure_on_one_endpoint_does_not_stop_the_rest():
    """A single Redis hiccup must not silence the whole tenant's fanout."""
    db     = MagicMock()
    redis  = AsyncMock()
    tenant = uuid4()

    eps = [_endpoint(), _endpoint(), _endpoint()]
    repo_instance = MagicMock()
    repo_instance.find_active_for_event = AsyncMock(return_value=eps)

    call_count = {"n": 0}

    async def flaky_enqueue(r, payload):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("redis blip")
        return "1-0"

    with patch.object(emitter, "WebhookEndpointRepository", return_value=repo_instance), \
         patch.object(emitter.webhook_queue, "enqueue", new=flaky_enqueue):

        n = await emit_from_audit(db=db, redis=redis, audit_data=_audit(tenant_id=tenant))

        assert n == 2
        assert call_count["n"] == 3
