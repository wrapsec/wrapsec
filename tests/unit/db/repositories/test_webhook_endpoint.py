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


# ─── Admin CRUD: create / get / list ────────────────────────────────

@pytest.mark.asyncio
async def test_create_persists_endpoint_with_defaults(test_db):
    t = await _make_tenant(test_db)
    repo = WebhookEndpointRepository(test_db)

    ep = await repo.create(
        tenant_id  = t.id,
        url        = "https://example.com/hook",
        secret_enc = "v2:encrypted-blob",
    )

    assert ep.id is not None
    assert ep.tenant_id == t.id
    assert ep.url == "https://example.com/hook"
    assert ep.secret_enc == "v2:encrypted-blob"
    assert ep.description is None
    assert ep.event_types is None       # wildcard by default
    assert ep.disabled is False
    assert ep.old_secrets == []
    assert ep.first_failure_at is None


@pytest.mark.asyncio
async def test_create_accepts_optional_description_and_event_types(test_db):
    t = await _make_tenant(test_db)
    repo = WebhookEndpointRepository(test_db)

    ep = await repo.create(
        tenant_id   = t.id,
        url         = "https://example.com/hook",
        secret_enc  = "v2:enc",
        description = "SOC pipeline",
        event_types = ["wrapsec.request.blocked"],
    )

    assert ep.description == "SOC pipeline"
    assert ep.event_types == ["wrapsec.request.blocked"]


@pytest.mark.asyncio
async def test_create_defaults_to_generic_webhook(test_db):
    """A create without connector_type is a generic HMAC webhook:
    connector_type and config are both NULL."""
    t = await _make_tenant(test_db)
    repo = WebhookEndpointRepository(test_db)

    ep = await repo.create(
        tenant_id  = t.id,
        url        = "https://example.com/hook",
        secret_enc = "v2:enc",
    )
    assert ep.connector_type is None
    assert ep.config is None


@pytest.mark.asyncio
async def test_create_persists_connector_type_and_config(test_db):
    t = await _make_tenant(test_db)
    repo = WebhookEndpointRepository(test_db)

    ep = await repo.create(
        tenant_id      = t.id,
        url            = "https://hec.example:8088",
        secret_enc     = "v2:hec-token",
        connector_type = "splunk_hec",
        config         = {"index": "security", "sourcetype": "wrapsec:security"},
    )
    assert ep.connector_type == "splunk_hec"
    assert ep.config == {"index": "security", "sourcetype": "wrapsec:security"}


@pytest.mark.asyncio
async def test_get_by_id_returns_row(test_db):
    t = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id)
    repo = WebhookEndpointRepository(test_db)

    result = await repo.get_by_id(ep.id)
    assert result is not None
    assert result.id == ep.id


@pytest.mark.asyncio
async def test_get_by_id_returns_none_for_missing(test_db):
    repo = WebhookEndpointRepository(test_db)
    assert await repo.get_by_id(uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_list_by_tenant_includes_disabled_and_scopes_to_tenant(test_db):
    """Admin UI needs to see disabled endpoints so operators can
    reactivate them; and MUST NOT see other tenants' endpoints."""
    t_a = await _make_tenant(test_db, "tenant-a")
    t_b = await _make_tenant(test_db, "tenant-b")

    live_a     = await _make_endpoint(test_db, t_a.id, disabled=False)
    disabled_a = await _make_endpoint(test_db, t_a.id, disabled=True)
    await _make_endpoint(test_db, t_b.id, disabled=False)

    repo = WebhookEndpointRepository(test_db)
    ids  = {ep.id for ep in await repo.list_by_tenant(t_a.id)}

    assert ids == {live_a.id, disabled_a.id}


# ─── Admin CRUD: update ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_changes_url_description_event_types(test_db):
    t  = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id, event_types=None)
    repo = WebhookEndpointRepository(test_db)

    updated = await repo.update(
        endpoint_id = ep.id,
        data        = {
            "url":         "https://new.example.com/hook",
            "description": "new desc",
            "event_types": ["wrapsec.request.blocked"],
        },
    )
    assert updated is not None
    assert updated.url == "https://new.example.com/hook"
    assert updated.description == "new desc"
    assert updated.event_types == ["wrapsec.request.blocked"]


@pytest.mark.asyncio
async def test_update_silently_drops_protected_fields(test_db):
    """Protected fields (secret_enc, disabled, first_failure_at,
    tenant_id, old_secrets) each have a dedicated call path with the
    right invariants. update() must NOT be a back-door around them --
    a caller sending disabled=True here MUST NOT bypass the manual
    reactivate flow, and a caller sending a raw secret_enc MUST NOT
    bypass the rotate-with-grace path."""
    t  = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id)
    repo = WebhookEndpointRepository(test_db)

    original_secret = ep.secret_enc
    original_disabled = ep.disabled

    updated = await repo.update(
        endpoint_id = ep.id,
        data        = {
            "url":              "https://ok.example.com",
            "secret_enc":       "v2:injected-secret",
            "disabled":         True,
            "first_failure_at": datetime.utcnow(),
            "tenant_id":        uuid.uuid4(),
            "old_secrets":      [{"ciphertext": "leak", "expires_at": "3000-01-01T00:00:00"}],
        },
    )
    assert updated.url == "https://ok.example.com"
    assert updated.secret_enc == original_secret
    assert updated.disabled == original_disabled
    assert updated.first_failure_at is None
    assert updated.tenant_id == t.id
    assert updated.old_secrets == [] or updated.old_secrets is None


@pytest.mark.asyncio
async def test_update_changes_config_but_not_connector_type(test_db):
    """config is an editable connector option; connector_type is
    immutable after create because it governs how secret_enc is
    interpreted. A caller trying to switch connector_type via update
    MUST be silently ignored."""
    t  = await _make_tenant(test_db)
    repo = WebhookEndpointRepository(test_db)
    ep = await repo.create(
        tenant_id      = t.id,
        url            = "https://hec.example:8088",
        secret_enc     = "v2:hec-token",
        connector_type = "splunk_hec",
        config         = {"index": "old"},
    )

    updated = await repo.update(
        endpoint_id = ep.id,
        data        = {
            "config":         {"index": "new", "sourcetype": "st"},
            "connector_type": "datadog_logs",
        },
    )
    assert updated.config == {"index": "new", "sourcetype": "st"}
    assert updated.connector_type == "splunk_hec"


@pytest.mark.asyncio
async def test_update_with_empty_data_is_a_noop(test_db):
    t  = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id)
    repo = WebhookEndpointRepository(test_db)

    result = await repo.update(endpoint_id=ep.id, data={})
    assert result is not None
    assert result.id == ep.id


# ─── Admin CRUD: delete ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_removes_row_and_returns_true(test_db):
    t  = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id)
    repo = WebhookEndpointRepository(test_db)

    assert await repo.delete(ep.id) is True
    assert await repo.get_by_id(ep.id) is None


@pytest.mark.asyncio
async def test_delete_missing_returns_false(test_db):
    """Idempotent-friendly for the API layer: delete of a non-existent
    id is not an error, the caller decides whether to return 404."""
    repo = WebhookEndpointRepository(test_db)
    assert await repo.delete(uuid.uuid4()) is False


# ─── Admin CRUD: rotate_secret ──────────────────────────────────────

@pytest.mark.asyncio
async def test_rotate_secret_stores_old_secret_with_expiry(test_db):
    """Rotation MUST preserve the old secret in old_secrets so a
    receiver mid-deploy keeps validating signatures during the grace
    window. Losing the old secret at rotation would break every
    receiver that has not yet redeployed."""
    t  = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id, url="https://x.example.com")
    repo = WebhookEndpointRepository(test_db)

    now = datetime(2026, 7, 29, 12, 0, 0)
    result = await repo.rotate_secret(
        endpoint_id    = ep.id,
        new_secret_enc = "v2:new-secret",
        grace_hours    = 24,
        now            = now,
    )
    assert result is not None
    assert result.secret_enc == "v2:new-secret"
    assert len(result.old_secrets) == 1
    entry = result.old_secrets[0]
    assert entry["ciphertext"] == "encrypted-blob"     # from _make_endpoint
    assert entry["expires_at"] == (now + timedelta(hours=24)).isoformat()


@pytest.mark.asyncio
async def test_rotate_secret_prunes_already_expired_old_secrets(test_db):
    """old_secrets MUST NOT grow unbounded across many rotations.
    Any entry whose expires_at has already passed is dropped in the
    same call so an endpoint rotated weekly for years still has an
    O(active-grace-windows) array, not O(total-rotations)."""
    t  = await _make_tenant(test_db)
    now = datetime(2026, 7, 29, 12, 0, 0)
    expired = {"ciphertext": "old-v1", "expires_at": (now - timedelta(hours=1)).isoformat()}
    live    = {"ciphertext": "old-v2", "expires_at": (now + timedelta(hours=10)).isoformat()}

    ep = WebhookEndpointModel(
        id          = uuid.uuid4(),
        tenant_id   = t.id,
        url         = "https://x.example.com",
        secret_enc  = "current",
        old_secrets = [expired, live],
        disabled    = False,
        created_at  = datetime.utcnow(),
    )
    test_db.add(ep)
    await test_db.flush()

    repo   = WebhookEndpointRepository(test_db)
    result = await repo.rotate_secret(
        endpoint_id    = ep.id,
        new_secret_enc = "brand-new",
        grace_hours    = 24,
        now            = now,
    )

    assert result.secret_enc == "brand-new"
    ciphertexts = [e["ciphertext"] for e in result.old_secrets]
    assert "old-v1" not in ciphertexts    # pruned
    assert "old-v2" in ciphertexts        # still in grace
    assert "current" in ciphertexts       # freshly rotated


@pytest.mark.asyncio
async def test_rotate_secret_missing_returns_none(test_db):
    repo = WebhookEndpointRepository(test_db)
    result = await repo.rotate_secret(
        endpoint_id    = uuid.uuid4(),
        new_secret_enc = "v2:x",
        grace_hours    = 24,
    )
    assert result is None


@pytest.mark.asyncio
async def test_rotate_secret_rejects_non_positive_grace(test_db):
    """A zero or negative grace window would invalidate the old secret
    the instant it moved into old_secrets, breaking receivers before
    they could redeploy. Surface loudly."""
    t  = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id)
    repo = WebhookEndpointRepository(test_db)

    with pytest.raises(ValueError):
        await repo.rotate_secret(endpoint_id=ep.id, new_secret_enc="v2:x", grace_hours=0)
    with pytest.raises(ValueError):
        await repo.rotate_secret(endpoint_id=ep.id, new_secret_enc="v2:x", grace_hours=-5)


# ─── Admin CRUD: reactivate ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_reactivate_clears_disabled_and_first_failure_at(test_db):
    """Manual recovery MUST clear BOTH flags -- otherwise the sweep
    would immediately re-disable the endpoint on the next tick with
    no new failures, which is opaque and infuriating."""
    t   = await _make_tenant(test_db)
    now = datetime(2026, 7, 29, 12, 0, 0)
    ep  = await _make_endpoint(
        test_db, t.id,
        disabled=True,
        first_failure_at=now - timedelta(days=10),
    )
    repo = WebhookEndpointRepository(test_db)

    result = await repo.reactivate(endpoint_id=ep.id, now=now)

    assert result is not None
    assert result.disabled is False
    assert result.first_failure_at is None


@pytest.mark.asyncio
async def test_reactivate_is_idempotent_on_active_endpoint(test_db):
    """Safe to call on an already-active endpoint. No-op, still 200."""
    t  = await _make_tenant(test_db)
    ep = await _make_endpoint(test_db, t.id, disabled=False)
    repo = WebhookEndpointRepository(test_db)

    result = await repo.reactivate(endpoint_id=ep.id)
    assert result is not None
    assert result.disabled is False


@pytest.mark.asyncio
async def test_reactivate_missing_returns_none(test_db):
    repo = WebhookEndpointRepository(test_db)
    assert await repo.reactivate(endpoint_id=uuid.uuid4()) is None
