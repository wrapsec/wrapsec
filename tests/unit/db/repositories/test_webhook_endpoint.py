# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Repository tests for WebhookEndpointRepository.

Two surface areas covered:

  1. find_active_for_event -- the emitter calls this once per
     BLOCK/SANITIZE decision (via BackgroundTasks, not the response
     path), so we pin the filter predicates that make the fanout
     correct: tenant isolation, disabled excluded, event_types
     wildcard vs explicit-list semantics.

  2. Circuit-breaker lifecycle (record_failure, record_success,
     disable_stale) -- these three methods maintain the
     first_failure_at timer that the sweep job reads. We pin the
     invariants that make the state machine safe:
       * record_failure MUST NOT reset the timer on subsequent
         failures (otherwise a flapping endpoint never gets disabled).
       * record_success MUST clear the timer (a recovered endpoint
         gets a fresh grace window).
       * disable_stale MUST leave healthy and already-disabled rows
         alone (idempotent, no false positives).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

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


async def _make_endpoint(
    db,
    tenant_id,
    *,
    event_types=None,
    disabled=False,
    url=None,
    first_failure_at=None,
):
    ep = WebhookEndpointModel(
        id               = uuid.uuid4(),
        tenant_id        = tenant_id,
        url              = url or f"https://example.com/{uuid.uuid4()}",
        description      = None,
        secret_enc       = "encrypted-blob",
        event_types      = event_types,
        disabled         = disabled,
        first_failure_at = first_failure_at,
        created_at       = datetime.utcnow(),
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


# ─── Circuit breaker: record_failure ────────────────────────────────

@pytest.mark.asyncio
async def test_record_failure_sets_first_failure_at_when_null(test_db):
    t   = await _make_tenant(test_db)
    ep  = await _make_endpoint(test_db, t.id)
    repo = WebhookEndpointRepository(test_db)

    fixed_now = datetime(2026, 7, 29, 12, 0, 0)
    await repo.record_failure(endpoint_id=ep.id, now=fixed_now)

    await test_db.refresh(ep)
    assert ep.first_failure_at == fixed_now


@pytest.mark.asyncio
async def test_record_failure_is_idempotent_and_preserves_first_timestamp(test_db):
    """The whole point of a 120h circuit breaker is that the timer
    counts from the FIRST failure, not the latest. If record_failure
    reset the timestamp on every call, a chronically flapping endpoint
    would never age out."""
    t   = await _make_tenant(test_db)
    ep  = await _make_endpoint(test_db, t.id)
    repo = WebhookEndpointRepository(test_db)

    t0 = datetime(2026, 7, 29, 12, 0, 0)
    t1 = t0 + timedelta(hours=1)
    t2 = t0 + timedelta(hours=50)

    await repo.record_failure(endpoint_id=ep.id, now=t0)
    await repo.record_failure(endpoint_id=ep.id, now=t1)
    await repo.record_failure(endpoint_id=ep.id, now=t2)

    await test_db.refresh(ep)
    assert ep.first_failure_at == t0


# ─── Circuit breaker: record_success ────────────────────────────────

@pytest.mark.asyncio
async def test_record_success_clears_first_failure_at(test_db):
    """A recovered endpoint gets a fresh grace window on the next
    outage -- otherwise a receiver that healed after 100h of pain
    would still be disabled at h=121 for reasons no operator remembers."""
    t = await _make_tenant(test_db)
    ep = await _make_endpoint(
        test_db, t.id,
        first_failure_at=datetime(2026, 7, 20, 12, 0, 0),
    )
    repo = WebhookEndpointRepository(test_db)

    await repo.record_success(endpoint_id=ep.id, now=datetime(2026, 7, 29, 12, 0, 0))

    await test_db.refresh(ep)
    assert ep.first_failure_at is None


@pytest.mark.asyncio
async def test_record_success_on_already_healthy_endpoint_is_a_noop(test_db):
    """Cheap to call on every 2xx: no-op when already NULL."""
    t = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id, first_failure_at=None)
    repo = WebhookEndpointRepository(test_db)

    await repo.record_success(endpoint_id=ep.id)

    await test_db.refresh(ep)
    assert ep.first_failure_at is None


# ─── Circuit breaker: disable_stale ─────────────────────────────────

@pytest.mark.asyncio
async def test_disable_stale_flips_only_endpoints_past_grace_window(test_db):
    """This is the whole load-bearing invariant of the sweep worker:
    stale rows get disabled, healthy and inside-grace rows do not."""
    t   = await _make_tenant(test_db)
    now = datetime(2026, 7, 29, 12, 0, 0)

    healthy      = await _make_endpoint(test_db, t.id, first_failure_at=None)
    fresh_fail   = await _make_endpoint(test_db, t.id, first_failure_at=now - timedelta(hours=1))
    inside_grace = await _make_endpoint(test_db, t.id, first_failure_at=now - timedelta(hours=119))
    stale        = await _make_endpoint(test_db, t.id, first_failure_at=now - timedelta(hours=121))
    very_stale   = await _make_endpoint(test_db, t.id, first_failure_at=now - timedelta(days=30))

    repo    = WebhookEndpointRepository(test_db)
    flipped = await repo.disable_stale(threshold_hours=120, now=now)

    assert set(flipped) == {stale.id, very_stale.id}

    for ep in (healthy, fresh_fail, inside_grace):
        await test_db.refresh(ep)
        assert ep.disabled is False, f"{ep.id} should still be enabled"

    for ep in (stale, very_stale):
        await test_db.refresh(ep)
        assert ep.disabled is True, f"{ep.id} should be disabled"


@pytest.mark.asyncio
async def test_disable_stale_ignores_already_disabled_endpoints(test_db):
    """Already-disabled rows are returned by neither the select nor the
    update -- the sweep is idempotent and never double-touches them."""
    t   = await _make_tenant(test_db)
    now = datetime(2026, 7, 29, 12, 0, 0)

    await _make_endpoint(
        test_db, t.id,
        first_failure_at=now - timedelta(days=30),
        disabled=True,
    )

    repo    = WebhookEndpointRepository(test_db)
    flipped = await repo.disable_stale(threshold_hours=120, now=now)
    assert flipped == []


@pytest.mark.asyncio
async def test_disable_stale_boundary_exactly_at_threshold(test_db):
    """Elapsed == threshold disables (matches should_disable semantics
    in services.webhooks.circuit_breaker)."""
    t   = await _make_tenant(test_db)
    now = datetime(2026, 7, 29, 12, 0, 0)
    ep  = await _make_endpoint(
        test_db, t.id,
        first_failure_at=now - timedelta(hours=120),
    )

    repo    = WebhookEndpointRepository(test_db)
    flipped = await repo.disable_stale(threshold_hours=120, now=now)

    assert flipped == [ep.id]
    await test_db.refresh(ep)
    assert ep.disabled is True


@pytest.mark.asyncio
async def test_disable_stale_returns_empty_when_nothing_matches(test_db):
    t   = await _make_tenant(test_db)
    now = datetime(2026, 7, 29, 12, 0, 0)
    await _make_endpoint(test_db, t.id, first_failure_at=None)
    await _make_endpoint(test_db, t.id, first_failure_at=now - timedelta(hours=10))

    repo    = WebhookEndpointRepository(test_db)
    flipped = await repo.disable_stale(threshold_hours=120, now=now)
    assert flipped == []


@pytest.mark.asyncio
async def test_disable_stale_rejects_non_positive_threshold(test_db):
    """A zero threshold would disable every endpoint on the next tick
    -- always a caller bug."""
    repo = WebhookEndpointRepository(test_db)
    with pytest.raises(ValueError):
        await repo.disable_stale(threshold_hours=0)
    with pytest.raises(ValueError):
        await repo.disable_stale(threshold_hours=-5)
