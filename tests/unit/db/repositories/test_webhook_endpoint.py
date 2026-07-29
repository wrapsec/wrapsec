# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Repository tests for WebhookEndpointRepository.find_active_for_event.

The emitter calls this once per BLOCK/SANITIZE decision, so these tests pin
the two filter predicates that make the fanout correct:

  1. Tenant isolation -- endpoints belonging to a different tenant are
     never returned. (Regression cover for the cross-tenant class of bug
     already guarded by test_cross_tenant_isolation.py for other repos.)
  2. Disabled endpoints are excluded (circuit-breaker path).
  3. event_types filter honors both wildcard (NULL == all events) and
     explicit-list semantics.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest

from db.models import TenantModel, WebhookEndpointModel
from db.repositories.webhook_endpoint import WebhookEndpointRepository


async def _make_tenant(db, slug="acme"):
    t = TenantModel(
        id            = uuid.uuid4(),
        slug          = slug,
        name          = slug.title(),
        global_policy = {},
        is_active     = True,
        created_at    = datetime.utcnow(),
    )
    db.add(t)
    await db.flush()
    return t


async def _make_endpoint(db, tenant_id, *, event_types=None, disabled=False, url=None):
    ep = WebhookEndpointModel(
        id          = uuid.uuid4(),
        tenant_id   = tenant_id,
        url         = url or f"https://example.com/{uuid.uuid4()}",
        description = None,
        secret_enc  = "encrypted-blob",
        event_types = event_types,
        disabled    = disabled,
        created_at  = datetime.utcnow(),
    )
    db.add(ep)
    await db.flush()
    return ep


@pytest.mark.asyncio
async def test_returns_only_endpoints_for_target_tenant(test_db):
    t_a = await _make_tenant(test_db, "tenant-a")
    t_b = await _make_tenant(test_db, "tenant-b")

    ep_a = await _make_endpoint(test_db, t_a.id, event_types=None)
    await _make_endpoint(test_db, t_b.id, event_types=None)

    repo = WebhookEndpointRepository(test_db)
    result = await repo.find_active_for_event(
        tenant_id  = t_a.id,
        event_type = "wrapsec.request.blocked",
    )

    ids = {ep.id for ep in result}
    assert ids == {ep_a.id}


@pytest.mark.asyncio
async def test_disabled_endpoint_is_excluded(test_db):
    t = await _make_tenant(test_db)
    live = await _make_endpoint(test_db, t.id, event_types=None, disabled=False)
    await _make_endpoint(test_db, t.id, event_types=None, disabled=True)

    repo = WebhookEndpointRepository(test_db)
    result = await repo.find_active_for_event(
        tenant_id  = t.id,
        event_type = "wrapsec.request.blocked",
    )

    assert [ep.id for ep in result] == [live.id]


@pytest.mark.asyncio
async def test_null_event_types_subscribes_to_everything(test_db):
    """event_types=None is the wildcard: subscribe to every current + future
    event without needing endpoint reconfiguration on each release."""
    t = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id, event_types=None)

    repo = WebhookEndpointRepository(test_db)
    for et in ["wrapsec.request.blocked", "wrapsec.request.sanitized", "made.up.event"]:
        result = await repo.find_active_for_event(tenant_id=t.id, event_type=et)
        assert [x.id for x in result] == [ep.id], f"wildcard should match {et}"


@pytest.mark.asyncio
async def test_explicit_event_types_filters_by_membership(test_db):
    t = await _make_tenant(test_db)
    blocked_only   = await _make_endpoint(test_db, t.id, event_types=["wrapsec.request.blocked"])
    sanitized_only = await _make_endpoint(test_db, t.id, event_types=["wrapsec.request.sanitized"])
    both           = await _make_endpoint(test_db, t.id, event_types=[
        "wrapsec.request.blocked", "wrapsec.request.sanitized",
    ])

    repo = WebhookEndpointRepository(test_db)

    ids_for_blocked = {ep.id for ep in await repo.find_active_for_event(
        tenant_id=t.id, event_type="wrapsec.request.blocked",
    )}
    assert ids_for_blocked == {blocked_only.id, both.id}

    ids_for_sanitized = {ep.id for ep in await repo.find_active_for_event(
        tenant_id=t.id, event_type="wrapsec.request.sanitized",
    )}
    assert ids_for_sanitized == {sanitized_only.id, both.id}

    # An unsubscribed event returns nothing (nobody listens).
    assert await repo.find_active_for_event(
        tenant_id=t.id, event_type="wrapsec.endpoint.disabled",
    ) == []
