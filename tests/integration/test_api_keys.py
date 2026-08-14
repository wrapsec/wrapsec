# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
import re
import uuid
from datetime import timedelta

import pytest

from services.time import to_iso_z, utc_now

# ISO-8601 UTC with a trailing Z and millisecond precision -- the wire contract
# every API/export/webhook timestamp must satisfy (services.time.to_iso_z).
_ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


async def _seed_api_key(test_db, *, expires_at):
    """Seed a usable (hash-matching) non-admin API key with the given expiry and
    return the raw key string to present as x-api-key. Own tenant+dept so the
    non-admin CheckConstraint is satisfied."""
    from db.models import APIKeyModel, DepartmentModel, TenantModel

    tid = uuid.uuid4()
    did = uuid.uuid4()
    raw = "wsk_live_" + uuid.uuid4().hex

    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await test_db.commit()
    test_db.add(DepartmentModel(id=did, tenant_id=tid, slug="d", name="D",
                                is_active=True))
    await test_db.commit()
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:8],
        tenant_id=tid, dept_id=did, name="k",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
        expires_at=expires_at,
    ))
    await test_db.commit()
    return raw


@pytest.mark.asyncio
async def test_key_created_at_is_iso_z(client, admin_jwt_headers, admin_key_scope):
    """Wire-contract regression: the API must emit timestamps as ISO-8601 UTC
    with a trailing Z (aware datetimes serialize to +00:00 by default; the
    endpoints route every timestamp through to_iso_z). Locks the actual response
    format, not just the helper."""
    response = await client.post(
        "/v1/keys",
        json={"name": "iso-z", "dept_id": admin_key_scope},
        headers=admin_jwt_headers,
    )
    assert response.status_code == 201, response.text
    created_at = response.json()["created_at"]
    assert _ISO_Z.match(created_at), f"created_at not ISO-Z: {created_at!r}"


@pytest.mark.asyncio
async def test_expired_api_key_rejected(client, test_db):
    """Aware-comparison regression: an API key past its expiry must be rejected.
    The check is `utc_now() > record.expires_at` against a TIMESTAMPTZ column
    (aware vs aware). A 401 -- rather than a 500 -- also proves the comparison
    does not raise the offset-naive/aware TypeError the migration could arm."""
    raw = await _seed_api_key(test_db, expires_at=utc_now() - timedelta(hours=1))
    r = await client.post(
        "/v1/ai/request",
        json={"input": "hello"},
        headers={"x-api-key": raw},
    )
    assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_create_key(client, admin_jwt_headers, admin_key_scope):
    response = await client.post(
        "/v1/keys",
        json={"name": "test-system", "dept_id": admin_key_scope},
        headers=admin_jwt_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "test-system"
    assert data["api_key"].startswith("wsk_live_")
    assert "key_id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_api_key_not_in_list(client, admin_jwt_headers, admin_key_scope):
    await client.post(
        "/v1/keys",
        json={"name": "test-system", "dept_id": admin_key_scope},
        headers=admin_jwt_headers,
    )
    response = await client.get("/v1/keys", headers=admin_jwt_headers)
    data = response.json()
    for key in data["keys"]:
        assert "api_key" not in key


@pytest.mark.asyncio
async def test_list_keys(client, admin_jwt_headers, admin_key_scope):
    await client.post(
        "/v1/keys",
        json={"name": "key-1", "dept_id": admin_key_scope},
        headers=admin_jwt_headers,
    )
    await client.post(
        "/v1/keys",
        json={"name": "key-2", "dept_id": admin_key_scope},
        headers=admin_jwt_headers,
    )

    response = await client.get("/v1/keys", headers=admin_jwt_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["keys"]) == 2


@pytest.mark.asyncio
async def test_revoke_key(client, admin_jwt_headers, admin_key_scope):
    create = await client.post(
        "/v1/keys",
        json={"name": "to-revoke", "dept_id": admin_key_scope},
        headers=admin_jwt_headers,
    )
    key_id = create.json()["key_id"]

    response = await client.delete(
        f"/v1/keys/{key_id}",
        headers=admin_jwt_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["revoked"] is True
    assert "revoked_at" in data


@pytest.mark.asyncio
async def test_revoked_key_excluded_from_list(client, admin_jwt_headers, admin_key_scope):
    create = await client.post(
        "/v1/keys",
        json={"name": "to-revoke", "dept_id": admin_key_scope},
        headers=admin_jwt_headers,
    )
    key_id = create.json()["key_id"]
    await client.delete(f"/v1/keys/{key_id}", headers=admin_jwt_headers)

    response = await client.get("/v1/keys", headers=admin_jwt_headers)
    data = response.json()
    assert all(k["key_id"] != key_id for k in data["keys"])


@pytest.mark.asyncio
async def test_revoke_nonexistent_key_returns_404(client, admin_jwt_headers):
    response = await client.delete(
        "/v1/keys/key_nonexistent",
        headers=admin_jwt_headers,
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_key_reads_are_dept_scoped_for_non_admin(client, test_db):
    """C1: a non-admin, dept-scoped principal sees only its own department's keys,
    and cannot read another department's key metadata."""
    from db.models import APIKeyModel, DepartmentModel, TenantModel

    tid = uuid.uuid4()
    dept_a, dept_b = uuid.uuid4(), uuid.uuid4()
    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await test_db.commit()
    for d in (dept_a, dept_b):
        test_db.add(DepartmentModel(id=d, tenant_id=tid, slug=f"d-{d.hex[:6]}", name="D", is_active=True))
    await test_db.commit()

    def _seed(dept, raw):
        kid = "key_" + uuid.uuid4().hex[:8]
        test_db.add(APIKeyModel(
            id=uuid.uuid4(), key_id=kid, tenant_id=tid, dept_id=dept, name="k",
            key_hash=hashlib.sha256(raw.encode()).hexdigest(),
            key_type="live", is_admin=False, revoked=False,
        ))
        return kid

    caller_raw = "wsk_live_" + uuid.uuid4().hex
    _seed(dept_a, caller_raw)                                  # the dept-A caller
    a_key = _seed(dept_a, "wsk_live_" + uuid.uuid4().hex)      # peer in dept A
    b_key = _seed(dept_b, "wsk_live_" + uuid.uuid4().hex)      # key in dept B
    await test_db.commit()

    hdr = {"x-api-key": caller_raw}
    listed = await client.get("/v1/keys", headers=hdr)
    assert listed.status_code == 200
    assert {k["dept_id"] for k in listed.json()["keys"]} == {str(dept_a)}   # own dept only
    assert b_key not in {k["key_id"] for k in listed.json()["keys"]}

    assert (await client.get(f"/v1/keys/{b_key}", headers=hdr)).status_code == 404  # cross-dept hidden
    assert (await client.get(f"/v1/keys/{a_key}", headers=hdr)).status_code == 200  # own dept visible


@pytest.mark.asyncio
async def test_create_key_persists_expires_at(client, admin_jwt_headers, admin_key_scope):
    """A1: a valid expires_at must be persisted, not silently dropped -- otherwise
    the key never expires while the response claims it will."""
    exp = to_iso_z(utc_now() + timedelta(hours=24))
    c = await client.post(
        "/v1/keys",
        json={"name": "expiring", "dept_id": admin_key_scope, "expires_at": exp},
        headers=admin_jwt_headers,
    )
    assert c.status_code == 201, c.text
    stored = c.json()["expires_at"]
    assert stored is not None                       # not dropped on create
    kid = c.json()["key_id"]
    g = await client.get(f"/v1/keys/{kid}", headers=admin_jwt_headers)
    assert g.json()["expires_at"] == stored         # read back from the DB


@pytest.mark.asyncio
async def test_create_key_without_dept_rejected(client, admin_jwt_headers):
    """H4: non-admin key with no dept_id must be rejected at endpoint (not DB)."""
    response = await client.post(
        "/v1/keys",
        json={"name": "no-scope"},
        headers=admin_jwt_headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


# ── helpers for app-scoped / cross-tenant / grace-state coverage ─────────────

def _admin_tenant_id(admin_jwt_headers) -> uuid.UUID:
    from services.auth.token import decode_access_token
    token = admin_jwt_headers["Authorization"].split()[1]
    return uuid.UUID(decode_access_token(token)["tenant_id"])


async def _make_app(test_db, tenant_id):
    """Create a dept + application under `tenant_id`; return (dept_id, app_id) strings."""
    from db.models import ApplicationModel, DepartmentModel

    did = uuid.uuid4()
    aid = uuid.uuid4()
    test_db.add(DepartmentModel(id=did, tenant_id=tenant_id, slug=f"d-{did.hex[:6]}",
                                name="Dept", is_active=True))
    await test_db.commit()
    test_db.add(ApplicationModel(id=aid, tenant_id=tenant_id, dept_id=did,
                                 slug=f"a-{aid.hex[:6]}", name="App", is_active=True))
    await test_db.commit()
    return str(did), str(aid)


async def _seed_key(test_db, *, tenant_id=None, expires_at=None, revoked=False):
    """Seed an APIKeyModel row with its own dept. When tenant_id is None a fresh
    (foreign) tenant is created -- used to prove cross-tenant reads 404.
    Returns key_id."""
    from db.models import APIKeyModel, DepartmentModel, TenantModel

    tid = tenant_id or uuid.uuid4()
    did = uuid.uuid4()
    if tenant_id is None:
        test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
        await test_db.commit()
    test_db.add(DepartmentModel(id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}",
                                name="D", is_active=True))
    await test_db.commit()
    kid = "key_" + uuid.uuid4().hex[:8]
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id=kid, tenant_id=tid, dept_id=did, name="seed",
        key_hash=hashlib.sha256(kid.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=revoked, expires_at=expires_at,
    ))
    await test_db.commit()
    return kid


# ── create: app-scoped chain + not-found + validation branches ───────────────

@pytest.mark.asyncio
async def test_create_app_scoped_key_derives_dept_and_tenant(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did, aid = await _make_app(test_db, tid)
    r = await client.post("/v1/keys", json={"name": "app-key", "app_id": aid}, headers=admin_jwt_headers)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["app_id"] == aid          # app_id echoed
    assert d["dept_id"] == did         # dept derived from the app record
    assert d["tenant_id"] == str(tid)  # tenant derived from the app record


@pytest.mark.asyncio
async def test_create_key_unknown_app_id_404(client, admin_jwt_headers):
    r = await client.post("/v1/keys", json={"name": "x", "app_id": str(uuid.uuid4())}, headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_key_cross_tenant_app_id_404(client, admin_jwt_headers, test_db):
    # App belongs to a different tenant -> the tenant-match guard must 404, never
    # let an admin mint a key scoped into someone else's tenant.
    from db.models import TenantModel
    other = uuid.uuid4()
    test_db.add(TenantModel(id=other, slug=f"t-{other.hex[:8]}", name="O"))
    await test_db.commit()
    _, aid = await _make_app(test_db, other)
    r = await client.post("/v1/keys", json={"name": "x", "app_id": aid}, headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_key_unknown_dept_id_404(client, admin_jwt_headers):
    r = await client.post("/v1/keys", json={"name": "x", "dept_id": str(uuid.uuid4())}, headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_key_invalid_dept_uuid_422(client, admin_jwt_headers):
    r = await client.post("/v1/keys", json={"name": "x", "dept_id": "not-a-uuid"}, headers=admin_jwt_headers)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_key_invalid_key_type_422(client, admin_jwt_headers, admin_key_scope):
    r = await client.post(
        "/v1/keys",
        json={"name": "x", "dept_id": admin_key_scope, "key_type": "bogus"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_key_invalid_expires_at_422(client, admin_jwt_headers, admin_key_scope):
    r = await client.post(
        "/v1/keys",
        json={"name": "x", "dept_id": admin_key_scope, "expires_at": "not-a-date"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_trial_key_has_trial_prefix(client, admin_jwt_headers, admin_key_scope):
    r = await client.post(
        "/v1/keys",
        json={"name": "t", "dept_id": admin_key_scope, "key_type": "trial"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["api_key"].startswith("wsk_trial_")
    assert r.json()["key_type"] == "trial"


# ── get single key ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_key_returns_metadata(client, admin_jwt_headers, admin_key_scope):
    c = await client.post("/v1/keys", json={"name": "g", "dept_id": admin_key_scope}, headers=admin_jwt_headers)
    kid = c.json()["key_id"]
    r = await client.get(f"/v1/keys/{kid}", headers=admin_jwt_headers)
    assert r.status_code == 200
    d = r.json()
    assert d["key_id"] == kid
    assert d["name"] == "g"
    assert d["revoked"] is False
    assert d["is_admin"] is False
    assert "api_key" not in d          # secret never returned on read


@pytest.mark.asyncio
async def test_get_key_nonexistent_404(client, admin_jwt_headers):
    r = await client.get("/v1/keys/key_nope", headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_key_cross_tenant_404(client, admin_jwt_headers, test_db):
    kid = await _seed_key(test_db)   # foreign tenant
    r = await client.get(f"/v1/keys/{kid}", headers=admin_jwt_headers)
    assert r.status_code == 404


# ── rename (update) ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_key_renames(client, admin_jwt_headers, admin_key_scope):
    c = await client.post("/v1/keys", json={"name": "old", "dept_id": admin_key_scope}, headers=admin_jwt_headers)
    kid = c.json()["key_id"]
    r = await client.put(f"/v1/keys/{kid}", json={"name": "new"}, headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["name"] == "new"
    g = await client.get(f"/v1/keys/{kid}", headers=admin_jwt_headers)
    assert g.json()["name"] == "new"


@pytest.mark.asyncio
async def test_update_key_nonexistent_404(client, admin_jwt_headers):
    r = await client.put("/v1/keys/key_nope", json={"name": "x"}, headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_update_key_cross_tenant_404(client, admin_jwt_headers, test_db):
    kid = await _seed_key(test_db)
    r = await client.put(f"/v1/keys/{kid}", json={"name": "x"}, headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_update_key_empty_name_422(client, admin_jwt_headers, admin_key_scope):
    c = await client.post("/v1/keys", json={"name": "old", "dept_id": admin_key_scope}, headers=admin_jwt_headers)
    kid = c.json()["key_id"]
    r = await client.put(f"/v1/keys/{kid}", json={"name": ""}, headers=admin_jwt_headers)
    assert r.status_code == 422


# ── delete: grace-period warning branch ──────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_key_in_grace_period_warns(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    kid = await _seed_key(test_db, tenant_id=tid, expires_at=utc_now() + timedelta(hours=1))
    r = await client.delete(f"/v1/keys/{kid}", headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["was_in_grace"] is True
    assert r.json()["warning"] is not None


# ── rotate ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rotate_key_success(client, admin_jwt_headers, admin_key_scope):
    c = await client.post("/v1/keys", json={"name": "r", "dept_id": admin_key_scope}, headers=admin_jwt_headers)
    kid, old_api = c.json()["key_id"], c.json()["api_key"]
    r = await client.post(f"/v1/keys/{kid}/rotate", json={"grace_period_minutes": 30}, headers=admin_jwt_headers)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["new_api_key"].startswith("wsk_live_")
    assert d["new_api_key"] != old_api        # a genuinely new secret
    assert d["new_key_id"] != kid
    assert d["old_key_id"] == kid
    assert d["grace_period_minutes"] == 30


@pytest.mark.asyncio
async def test_rotate_key_grace_zero_immediate(client, admin_jwt_headers, admin_key_scope):
    c = await client.post("/v1/keys", json={"name": "r0", "dept_id": admin_key_scope}, headers=admin_jwt_headers)
    kid = c.json()["key_id"]
    r = await client.post(f"/v1/keys/{kid}/rotate", json={"grace_period_minutes": 0}, headers=admin_jwt_headers)
    assert r.status_code == 201
    assert r.json()["grace_period_minutes"] == 0


@pytest.mark.asyncio
async def test_rotate_key_grace_out_of_bounds_422(client, admin_jwt_headers, admin_key_scope):
    c = await client.post("/v1/keys", json={"name": "rb", "dept_id": admin_key_scope}, headers=admin_jwt_headers)
    kid = c.json()["key_id"]
    r = await client.post(f"/v1/keys/{kid}/rotate", json={"grace_period_minutes": 99999}, headers=admin_jwt_headers)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_rotate_revoked_key_404(client, admin_jwt_headers, admin_key_scope):
    # A revoked key cannot be rotated. The lookup (get_active_by_key_id) filters
    # revoked == False, so a revoked key resolves to None and the endpoint 404s
    # before reaching its KEY_REVOKED branch (that branch is therefore
    # unreachable via this path). 404 also avoids confirming the key existed.
    c = await client.post("/v1/keys", json={"name": "rv", "dept_id": admin_key_scope}, headers=admin_jwt_headers)
    kid = c.json()["key_id"]
    await client.delete(f"/v1/keys/{kid}", headers=admin_jwt_headers)
    r = await client.post(f"/v1/keys/{kid}/rotate", json={}, headers=admin_jwt_headers)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_rotate_key_already_in_grace_400(client, admin_jwt_headers, admin_key_scope):
    c = await client.post("/v1/keys", json={"name": "rg", "dept_id": admin_key_scope}, headers=admin_jwt_headers)
    kid = c.json()["key_id"]
    await client.post(f"/v1/keys/{kid}/rotate", json={"grace_period_minutes": 60}, headers=admin_jwt_headers)
    # Rotating the OLD key again -> it is now in its grace window -> rejected.
    r = await client.post(f"/v1/keys/{kid}/rotate", json={}, headers=admin_jwt_headers)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "KEY_IN_GRACE_PERIOD"


@pytest.mark.asyncio
async def test_rotate_key_grace_expired_400(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    kid = await _seed_key(test_db, tenant_id=tid, expires_at=utc_now() - timedelta(hours=1))
    r = await client.post(f"/v1/keys/{kid}/rotate", json={}, headers=admin_jwt_headers)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "KEY_EXPIRED"


@pytest.mark.asyncio
async def test_rotate_key_nonexistent_404(client, admin_jwt_headers):
    r = await client.post("/v1/keys/key_nope/rotate", json={}, headers=admin_jwt_headers)
    assert r.status_code == 404


# ── list enrichment (dept_name / app_name join) ──────────────────────────────

@pytest.mark.asyncio
async def test_list_keys_enriched_with_dept_and_app_names(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did, aid = await _make_app(test_db, tid)
    await client.post("/v1/keys", json={"name": "enr", "app_id": aid}, headers=admin_jwt_headers)
    r = await client.get("/v1/keys", headers=admin_jwt_headers)
    assert r.status_code == 200
    match = [k for k in r.json()["keys"] if k["app_id"] == aid]
    assert match, "app-scoped key not present in listing"
    assert match[0]["dept_id"] == did
    assert match[0]["dept_name"] == "Dept"
    assert match[0]["app_name"] == "App"
