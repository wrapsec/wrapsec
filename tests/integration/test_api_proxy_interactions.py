# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Access-boundary tests for the proxy interactions read endpoints
(GET /v1/proxy/interactions, GET /v1/proxy/interactions/{trace_id}).

Key-id format -- the subtle part the original admin path got wrong:

    api_keys.key_id              = "abc123"       (raw, what the table is indexed by)
    request.state.key_id         = "key:abc123"   (prefixed principal id set by auth)
    ProxyInteractionModel.key_id = "key:abc123"   (stored as the prefixed principal id)

The caller-scoped path compares stored prefixed id vs request.state.key_id (prefixed
vs prefixed). The admin path must resolve the prefixed id back to the raw key_id before
it hits api_keys -- otherwise a tenant-scoped admin sees NONE of the tenant's real,
API-key-attributed interactions. test_admin_lists_own_tenant_and_isolates_cross_tenant
reproduces exactly that case with a real tenant-scoped API key.
"""

import hashlib
import uuid

import pytest

from db.models import APIKeyModel, DepartmentModel, ProxyInteractionModel, TenantModel


async def _seed_tenant(db):
    tid = uuid.uuid4()
    db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T",
                       global_policy={}, is_active=True))
    await db.commit()
    return tid


async def _seed_api_key(db, tenant_id=None):
    """Seed a usable (hash-matching) non-admin API key. Returns (raw_key, key_id, tenant_id)."""
    if tenant_id is None:
        tenant_id = await _seed_tenant(db)
    did = uuid.uuid4()
    db.add(DepartmentModel(id=did, tenant_id=tenant_id, slug=f"d-{did.hex[:6]}",
                           name="D", is_active=True))
    await db.commit()
    raw    = "wsk_live_" + uuid.uuid4().hex
    key_id = "key_" + uuid.uuid4().hex[:8]
    db.add(APIKeyModel(
        id=uuid.uuid4(), key_id=key_id, tenant_id=tenant_id, dept_id=did, name="k",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False, expires_at=None,
    ))
    await db.commit()
    return raw, key_id, tenant_id


async def _seed_interaction(db, *, key_id, trace_id=None, execution_status="completed"):
    """Seed a proxy interaction. key_id is the stored (prefixed) principal id, or None
    for a system record. Attribution (tenant/dept/app) is derived from the seeded key,
    mirroring production _log_interaction which stores it directly on the row."""
    trace_id = trace_id or ("tr-" + uuid.uuid4().hex[:12])
    tenant_id = dept_id = app_id = None
    if key_id:
        from sqlalchemy import select

        from db.models import APIKeyModel
        rec = (await db.execute(
            select(APIKeyModel).where(APIKeyModel.key_id == key_id.removeprefix("key:"))
        )).scalar_one_or_none()
        if rec:
            tenant_id, dept_id, app_id = rec.tenant_id, rec.dept_id, rec.app_id
    db.add(ProxyInteractionModel(
        id=uuid.uuid4(), trace_id=trace_id, key_id=key_id,
        tenant_id=tenant_id, dept_id=dept_id, app_id=app_id,
        input_decision="ALLOW", input_primary_reason="NO_THREAT_DETECTED",
        input_confidence=0.0, execution_status=execution_status, total_latency_ms=42,
        input_raw="RAW_IN", input_sanitized="SAN_IN",
        output_raw="RAW_OUT", output_sanitized="SAN_OUT",
    ))
    await db.commit()
    return trace_id


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


_RAW_FIELDS = ("input_raw", "input_sanitized", "output_raw", "output_sanitized")


# ── Caller-scoped (non-admin API key) boundary ──────────────────────────────

@pytest.mark.asyncio
async def test_nonadmin_lists_only_own_key_and_hides_raw_fields(client, test_db):
    raw, key_id, tid = await _seed_api_key(test_db)
    _, other_key_id, _ = await _seed_api_key(test_db, tid)  # same tenant, different key

    own    = await _seed_interaction(test_db, key_id=f"key:{key_id}")
    other  = await _seed_interaction(test_db, key_id=f"key:{other_key_id}")
    system = await _seed_interaction(test_db, key_id=None)

    r = await client.get("/v1/proxy/interactions", headers={"x-api-key": raw})
    assert r.status_code == 200, r.text
    items  = r.json()["items"]
    traces = {it["trace_id"] for it in items}
    assert own in traces
    assert other not in traces    # another key in the same tenant is not the caller's
    assert system not in traces   # system records are never caller-visible

    own_item = next(it for it in items if it["trace_id"] == own)
    # raw/sanitized text MUST NOT appear in list items ...
    for f in _RAW_FIELDS:
        assert f not in own_item
    # ... and key_id is returned in the raw (documented) form, not "key:<id>"
    assert own_item["key_id"] == key_id


@pytest.mark.asyncio
async def test_nonadmin_detail_own_includes_raw_fields(client, test_db):
    raw, key_id, _ = await _seed_api_key(test_db)
    trace = await _seed_interaction(test_db, key_id=f"key:{key_id}")

    r = await client.get(f"/v1/proxy/interactions/{trace}", headers={"x-api-key": raw})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["trace_id"] == trace
    assert body["key_id"] == key_id
    assert body["input_raw"] == "RAW_IN"
    assert body["output_raw"] == "RAW_OUT"


@pytest.mark.asyncio
async def test_nonadmin_detail_other_key_returns_404(client, test_db):
    raw, _, tid = await _seed_api_key(test_db)
    _, other_key_id, _ = await _seed_api_key(test_db, tid)
    other = await _seed_interaction(test_db, key_id=f"key:{other_key_id}")

    r = await client.get(f"/v1/proxy/interactions/{other}", headers={"x-api-key": raw})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_nonadmin_detail_system_record_returns_404(client, test_db):
    raw, _, _ = await _seed_api_key(test_db)
    system = await _seed_interaction(test_db, key_id=None)

    r = await client.get(f"/v1/proxy/interactions/{system}", headers={"x-api-key": raw})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_detail_missing_returns_404(client, test_db):
    raw, _, _ = await _seed_api_key(test_db)
    r = await client.get("/v1/proxy/interactions/does-not-exist", headers={"x-api-key": raw})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_list_pagination_clamps(client, test_db):
    raw, _, _ = await _seed_api_key(test_db)
    r = await client.get(
        "/v1/proxy/interactions?limit=9999&offset=-5", headers={"x-api-key": raw}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["limit"] == 200   # clamped to the max
    assert body["offset"] == 0    # clamped to non-negative

    r2 = await client.get("/v1/proxy/interactions?limit=0", headers={"x-api-key": raw})
    assert r2.json()["limit"] == 1  # clamped to the min


@pytest.mark.asyncio
async def test_list_execution_status_filter(client, test_db):
    raw, key_id, _ = await _seed_api_key(test_db)
    ok   = await _seed_interaction(test_db, key_id=f"key:{key_id}", execution_status="completed")
    fail = await _seed_interaction(test_db, key_id=f"key:{key_id}", execution_status="provider_error")

    r = await client.get(
        "/v1/proxy/interactions?execution_status=provider_error", headers={"x-api-key": raw}
    )
    assert r.status_code == 200, r.text
    traces = {it["trace_id"] for it in r.json()["items"]}
    assert fail in traces
    assert ok not in traces


# ── Role / tenant boundary (JWT) ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_lists_own_tenant_and_isolates_cross_tenant(client, test_db, auth_setup):
    """Reproduces the original bug: a tenant-scoped ADMIN must see interactions attributed
    to a REAL API key in their tenant. The stored id is "key:<id>" but api_keys stores the
    raw <id>; before the fix the admin tenant scope matched nothing."""
    tenant = auth_setup["tenant"].id

    _, own_key_id, _ = await _seed_api_key(test_db, tenant)          # real tenant-scoped key
    own = await _seed_interaction(test_db, key_id=f"key:{own_key_id}")

    _, other_key_id, _ = await _seed_api_key(test_db)               # a different tenant
    other = await _seed_interaction(test_db, key_id=f"key:{other_key_id}")

    r = await client.get("/v1/proxy/interactions", headers=_bearer(auth_setup["admin_token"]))
    assert r.status_code == 200, r.text
    items  = r.json()["items"]
    traces = {it["trace_id"] for it in items}
    assert own in traces          # <-- the regression fix
    assert other not in traces    # cross-tenant isolation

    own_item = next(it for it in items if it["trace_id"] == own)
    for f in _RAW_FIELDS:
        assert f not in own_item          # raw fields absent from list
    assert own_item["key_id"] == own_key_id


@pytest.mark.asyncio
async def test_nonadmin_reader_scoped_by_current_rbac(client, test_db, auth_setup):
    """A VIEWER (non-admin reader) is authenticated (not 403) but scoped to their own
    principal id ("user:<id>"), which no key-attributed interaction carries -- so per
    current RBAC they see none of the tenant's proxy interactions. Only ADMIN gets
    tenant-wide visibility."""
    tenant = auth_setup["tenant"].id
    _, key_id, _ = await _seed_api_key(test_db, tenant)
    await _seed_interaction(test_db, key_id=f"key:{key_id}")

    r = await client.get("/v1/proxy/interactions", headers=_bearer(auth_setup["viewer_token"]))
    assert r.status_code == 200, r.text   # allowed to call
    assert r.json()["items"] == []        # but scoped away from key-attributed rows


@pytest.mark.asyncio
async def test_admin_detail_includes_raw_and_cross_tenant_404(client, test_db, auth_setup):
    tenant = auth_setup["tenant"].id
    _, own_key_id, _ = await _seed_api_key(test_db, tenant)
    own = await _seed_interaction(test_db, key_id=f"key:{own_key_id}")

    _, other_key_id, _ = await _seed_api_key(test_db)
    other = await _seed_interaction(test_db, key_id=f"key:{other_key_id}")

    r_own = await client.get(f"/v1/proxy/interactions/{own}", headers=_bearer(auth_setup["admin_token"]))
    assert r_own.status_code == 200, r_own.text
    assert r_own.json()["input_raw"] == "RAW_IN"   # detail exposes raw fields
    assert r_own.json()["key_id"] == own_key_id

    r_other = await client.get(f"/v1/proxy/interactions/{other}", headers=_bearer(auth_setup["admin_token"]))
    assert r_other.status_code == 404              # cross-tenant not exposed


@pytest.mark.asyncio
async def test_admin_detail_survives_deleted_key(client, test_db, auth_setup):
    """M5: interaction history stays visible after its key is deleted. The tenant
    check reads the stored tenant_id, not a live api_keys join, so revoked/removed
    keys no longer erase their own history (the old join returned 404)."""
    from sqlalchemy import delete as sa_delete

    from db.models import APIKeyModel

    tenant = auth_setup["tenant"].id
    _, key_id, _ = await _seed_api_key(test_db, tenant)
    trace = await _seed_interaction(test_db, key_id=f"key:{key_id}")

    # Delete the key entirely -- harder than a revoke; the old join would find nothing.
    await test_db.execute(sa_delete(APIKeyModel).where(APIKeyModel.key_id == key_id))
    await test_db.commit()

    r = await client.get(f"/v1/proxy/interactions/{trace}", headers=_bearer(auth_setup["admin_token"]))
    assert r.status_code == 200, r.text
    assert r.json()["input_raw"] == "RAW_IN"
