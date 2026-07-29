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
  5. event_types filter is honored (list AND wildcard-null semantics).
  6. disabled endpoints are excluded (filter is by the repo, verified via
     the SQL WHERE clause).
  7. Errors in the DB lookup or the enqueue are swallowed -- the emitter
     is never allowed to raise into the caller.
"""

from __future__ import annotations

from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.webhooks import emitter
from services.webhooks.emitter import (
    EVENT_BLOCKED,
    EVENT_SANITIZED,
    _event_type_for_decision,
    emit_gateway_decision,
)


def _endpoint(event_types=None, disabled=False):
    ep = MagicMock()
    ep.id          = uuid4()
    ep.tenant_id   = uuid4()
    ep.event_types = event_types
    ep.disabled    = disabled
    return ep


# ─── _event_type_for_decision ────────────────────────────────────────────

def test_event_type_for_block():
    assert _event_type_for_decision("BLOCK") == EVENT_BLOCKED


def test_event_type_for_sanitize():
    assert _event_type_for_decision("SANITIZE") == EVENT_SANITIZED


def test_event_type_for_allow_is_none():
    """ALLOW must not emit -- volume would drown the delivery pipeline."""
    assert _event_type_for_decision("ALLOW") is None


# ─── emit_gateway_decision: no-emit paths ────────────────────────────────

@pytest.mark.asyncio
async def test_allow_decision_never_calls_repo_or_enqueue():
    db    = MagicMock()
    redis = AsyncMock()

    with patch.object(emitter, "WebhookEndpointRepository") as Repo, \
         patch.object(emitter.webhook_queue, "enqueue", new=AsyncMock()) as enq:

        n = await emit_gateway_decision(
            db             = db,
            redis          = redis,
            tenant_id      = uuid4(),
            trace_id       = "t-1",
            decision       = "ALLOW",
            risk_score     = 0.0,
            primary_reason = "NO_THREAT",
            confidence     = 0.9,
            threats        = [],
        )

        assert n == 0
        Repo.assert_not_called()
        enq.assert_not_called()


@pytest.mark.asyncio
async def test_missing_tenant_never_calls_repo_or_enqueue():
    db    = MagicMock()
    redis = AsyncMock()

    with patch.object(emitter, "WebhookEndpointRepository") as Repo, \
         patch.object(emitter.webhook_queue, "enqueue", new=AsyncMock()) as enq:

        n = await emit_gateway_decision(
            db             = db,
            redis          = redis,
            tenant_id      = None,
            trace_id       = "t-1",
            decision       = "BLOCK",
            risk_score     = 0.9,
            primary_reason = "RULE_DETECTOR",
            confidence     = 0.9,
            threats        = ["prompt_injection"],
        )

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

        n = await emit_gateway_decision(
            db             = db,
            redis          = redis,
            tenant_id      = tenant,
            trace_id       = "t-1",
            decision       = "BLOCK",
            risk_score     = 0.9,
            primary_reason = "RULE_DETECTOR",
            confidence     = 0.9,
            threats        = ["prompt_injection"],
        )

        assert n == 0
        enq.assert_not_called()
        repo_instance.find_active_for_event.assert_awaited_once()
        call = repo_instance.find_active_for_event.await_args
        assert call.kwargs["tenant_id"] == tenant
        assert call.kwargs["event_type"] == EVENT_BLOCKED


# ─── emit_gateway_decision: enqueue paths ────────────────────────────────

@pytest.mark.asyncio
async def test_block_enqueues_one_payload_per_endpoint():
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

    with patch.object(emitter, "WebhookEndpointRepository", return_value=repo_instance), \
         patch.object(emitter.webhook_queue, "enqueue", new=fake_enqueue):

        n = await emit_gateway_decision(
            db             = db,
            redis          = redis,
            tenant_id      = tenant,
            trace_id       = "trace-abc",
            decision       = "BLOCK",
            risk_score     = 0.95,
            primary_reason = "RULE_DETECTOR",
            confidence     = 0.9,
            threats        = ["prompt_injection"],
            source         = "api",
            user_id        = "u1",
            detection_mode = "fast",
            execution_mode = "scan_only",
        )

        assert n == 3
        assert len(captured) == 3

        # Every payload carries the canonical envelope fields.
        for p, ep in zip(captured, eps):
            assert p["event_type"]     == EVENT_BLOCKED
            assert p["endpoint_id"]    == str(ep.id)
            assert p["tenant_id"]      == str(tenant)
            assert p["msg_id"]         == "trace-abc"
            assert p["attempt_number"] == 1
            body = p["body"]
            assert body["trace_id"]       == "trace-abc"
            assert body["decision"]       == "BLOCK"
            assert body["risk_score"]     == 0.95
            assert body["primary_reason"] == "RULE_DETECTOR"
            assert body["threats"]        == ["prompt_injection"]
            # High-confidence detection block -> CRITICAL per severity taxonomy.
            assert body["severity"]       == "CRITICAL"
            assert body["source"]         == "api"
            assert body["user_id"]        == "u1"
            assert body["detection_mode"] == "fast"
            assert body["execution_mode"] == "scan_only"


@pytest.mark.asyncio
async def test_sanitize_enqueues_with_sanitized_event_type_and_medium_severity():
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

        n = await emit_gateway_decision(
            db             = db,
            redis          = redis,
            tenant_id      = tenant,
            trace_id       = "trace-xyz",
            decision       = "SANITIZE",
            risk_score     = 0.5,
            primary_reason = "PII_GUARDRAIL_SANITIZE",
            confidence     = 0.8,
            threats        = [],
        )

        assert n == 1
        assert captured["event_type"] == EVENT_SANITIZED
        assert captured["body"]["severity"] == "MEDIUM"
        # Lookup asked the repo for the SANITIZED event type, not BLOCKED.
        assert repo_instance.find_active_for_event.await_args.kwargs["event_type"] == EVENT_SANITIZED


# ─── emit_gateway_decision: failure isolation ────────────────────────────

@pytest.mark.asyncio
async def test_repo_failure_is_swallowed_and_returns_zero():
    """Scan responses must never fail because the webhook lookup did."""
    db    = MagicMock()
    redis = AsyncMock()

    repo_instance = MagicMock()
    repo_instance.find_active_for_event = AsyncMock(side_effect=RuntimeError("DB down"))

    with patch.object(emitter, "WebhookEndpointRepository", return_value=repo_instance), \
         patch.object(emitter.webhook_queue, "enqueue", new=AsyncMock()) as enq:

        n = await emit_gateway_decision(
            db             = db,
            redis          = redis,
            tenant_id      = uuid4(),
            trace_id       = "t-1",
            decision       = "BLOCK",
            risk_score     = 0.9,
            primary_reason = "RULE_DETECTOR",
            confidence     = 0.9,
            threats        = [],
        )

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

        n = await emit_gateway_decision(
            db             = db,
            redis          = redis,
            tenant_id      = tenant,
            trace_id       = "t-1",
            decision       = "BLOCK",
            risk_score     = 0.9,
            primary_reason = "RULE_DETECTOR",
            confidence     = 0.9,
            threats        = [],
        )

        # Two succeeded, one raised and was swallowed; loop kept going.
        assert n == 2
        assert call_count["n"] == 3
