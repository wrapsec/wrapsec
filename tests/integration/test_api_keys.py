# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
import re
import uuid
from datetime import timedelta

import pytest

from services.time import utc_now

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

    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T",
                            global_policy={}, is_active=True))
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
async def test_create_key_without_dept_rejected(client, admin_jwt_headers):
    """H4: non-admin key with no dept_id must be rejected at endpoint (not DB)."""
    response = await client.post(
        "/v1/keys",
        json={"name": "no-scope"},
        headers=admin_jwt_headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
