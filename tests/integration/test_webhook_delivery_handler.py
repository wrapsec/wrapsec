# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for the concrete webhook delivery handler (v1.3.0, 12b.4).

Runs on the disposable Postgres harness (see tests/integration/conftest.py):
a real webhook_endpoints row, a real webhook_delivery_attempts write, and
the real circuit-breaker timer, with only the outbound HTTP client stubbed.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from config.settings import get_settings
from db.models import TenantModel, WebhookDeliveryAttemptModel, WebhookEndpointModel
from security.encryption import encrypt
from services.webhooks import delivery_handler as dh
from services.webhooks.delivery_handler import WebhookDeliveryHandler
from services.webhooks.retry_schedule import MAX_ATTEMPTS
from workers.webhook_delivery import DeliveryResult


class _FakeResp:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class _FakeHTTPClient:
    def __init__(self, response):
        self.response = response
        self.last = None

    async def request(self, method, url, headers=None, content=None):
        self.last = {"method": method, "url": url, "headers": headers, "content": content}
        return self.response


async def _seed_endpoint(db) -> WebhookEndpointModel:
    tenant_id = uuid.uuid4()
    db.add(TenantModel(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", name="T",
                       global_policy={}, is_active=True))
    ep = WebhookEndpointModel(
        id=uuid.uuid4(), tenant_id=tenant_id, url="https://recv.example/hook",
        secret_enc=encrypt("sk_secret", get_settings().secret_key),
        old_secrets=[], event_types=None, disabled=False,
    )
    db.add(ep)
    await db.commit()
    return ep


def _handler(response):
    h = WebhookDeliveryHandler(session_factory=None, redis=SimpleNamespace(),
                               timeout_s=10, max_response_bytes=2048)
    h._client = _FakeHTTPClient(response)
    return h


def _payload(ep, attempt_number=1):
    return {
        "endpoint_id": str(ep.id), "tenant_id": str(ep.tenant_id),
        "msg_id": "m-1", "event_type": "wrapsec.request.blocked",
        "attempt_number": attempt_number,
        "body": {"trace_id": "t-1", "decision": "BLOCK", "severity": "HIGH"},
    }


async def _attempts(db, ep):
    rows = (await db.execute(
        select(WebhookDeliveryAttemptModel)
        .where(WebhookDeliveryAttemptModel.endpoint_id == ep.id)
    )).scalars().all()
    return rows


@pytest.mark.asyncio
async def test_success_records_attempt_and_clears_failure_timer(test_db):
    ep = await _seed_endpoint(test_db)
    # Pre-set a failure timer to prove success clears it.
    ep.first_failure_at = __import__("datetime").datetime.utcnow()
    await test_db.commit()

    handler = _handler(_FakeResp(200, "ok"))
    outcome = await handler._handle(test_db, _payload(ep))

    assert outcome.result is DeliveryResult.SUCCESS
    rows = await _attempts(test_db, ep)
    assert len(rows) == 1
    assert rows[0].status == "success"
    assert rows[0].http_status_code == 200
    await test_db.refresh(ep)   # reload true DB state (async-safe)
    assert ep.first_failure_at is None


@pytest.mark.asyncio
async def test_transient_failure_schedules_retry_and_sets_timer(test_db):
    ep = await _seed_endpoint(test_db)
    handler = _handler(_FakeResp(503, "unavailable"))
    outcome = await handler._handle(test_db, _payload(ep, attempt_number=1))

    assert outcome.result is DeliveryResult.RETRY
    assert outcome.retry_in_s == 5          # first retry slot
    rows = await _attempts(test_db, ep)
    assert rows[0].status == "failed"
    assert rows[0].http_status_code == 503
    assert rows[0].next_attempt_at is not None
    await test_db.refresh(ep)   # reload true DB state (async-safe)
    assert ep.first_failure_at is not None   # circuit-breaker timer started


@pytest.mark.asyncio
async def test_retries_exhausted_dead_letters(test_db):
    ep = await _seed_endpoint(test_db)
    handler = _handler(_FakeResp(500))
    # The last allowed attempt: next_retry_delay returns None -> DLQ.
    outcome = await handler._handle(test_db, _payload(ep, attempt_number=MAX_ATTEMPTS))

    assert outcome.result is DeliveryResult.DLQ
    assert outcome.dlq_reason == "retries_exhausted"
    rows = await _attempts(test_db, ep)
    assert rows[0].status == "dead"


@pytest.mark.asyncio
async def test_disabled_endpoint_dead_letters(test_db):
    ep = await _seed_endpoint(test_db)
    ep.disabled = True
    await test_db.commit()

    handler = _handler(_FakeResp(200))
    outcome = await handler._handle(test_db, _payload(ep))

    assert outcome.result is DeliveryResult.DLQ
    assert outcome.dlq_reason == "endpoint_disabled"
    assert handler._client.last is None      # never attempted the POST
    rows = await _attempts(test_db, ep)
    assert rows[0].status == "dead"


@pytest.mark.asyncio
async def test_deleted_endpoint_dead_letters_without_row(test_db):
    ep = await _seed_endpoint(test_db)
    payload = _payload(ep)
    await test_db.delete(ep)
    await test_db.commit()

    handler = _handler(_FakeResp(200))
    outcome = await handler._handle(test_db, payload)

    assert outcome.result is DeliveryResult.DLQ
    assert outcome.dlq_reason == "endpoint_deleted"
