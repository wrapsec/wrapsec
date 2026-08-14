# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration coverage for the application admin endpoints (mounted at
/v1/admin/applications). Slug canonicalization/conflict, cross-tenant 404 guards,
tenant-scoped listing, and RBAC live in test_api_slug / test_cross_tenant_isolation /
test_rbac_role_matrix; this file targets the handler logic those do not:
department validation on create, environment validation, dept-filtered listing,
secret masking on read, partial update + admin-event, soft delete, effective-policy
resolution, the set/reset full-override endpoints, and the LLM/proxy PATCH endpoints.
"""

import uuid

import pytest

from config.settings import get_settings
from security.encryption import encrypt

BASE = "/v1/admin/applications"


def _admin_tenant_id(admin_jwt_headers) -> uuid.UUID:
    from services.auth.token import decode_access_token
    token = admin_jwt_headers["Authorization"].split()[1]
    return uuid.UUID(decode_access_token(token)["tenant_id"])


async def _make_dept(test_db, tenant_id) -> str:
    from db.models import DepartmentModel
    did = uuid.uuid4()
    test_db.add(DepartmentModel(
        id=did, tenant_id=tenant_id, slug=f"d-{did.hex[:6]}", name="Dept", is_active=True,
    ))
    await test_db.commit()
    return str(did)


async def _seed_app(test_db, tenant_id, dept_id, *, policy_override=None) -> str:
    """Insert an application directly (used when it must carry a pre-encrypted
    policy_override). Returns app_id (str)."""
    from db.models import ApplicationModel
    aid = uuid.uuid4()
    test_db.add(ApplicationModel(
        id=aid, tenant_id=tenant_id, dept_id=uuid.UUID(dept_id),
        slug=f"seed-{aid.hex[:6]}", name="Seed", is_active=True,
        policy_override=policy_override,
    ))
    await test_db.commit()
    return str(aid)


async def _create_app(client, headers, dept_id, *, slug, **extra) -> str:
    body = {"dept_id": dept_id, "slug": slug, "name": "App", **extra}
    r = await client.post(BASE, json=body, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ── create: dept validation + field validation ──────────────────────────────

@pytest.mark.asyncio
async def test_create_application_success(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    r = await client.post(BASE, json={"dept_id": did, "slug": "Billing Svc", "name": "Billing"}, headers=admin_jwt_headers)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["slug"] == "billing-svc"          # canonicalized server-side
    assert d["dept_id"] == did
    assert d["environment"] == "production"    # default
    assert d["is_active"] is True


@pytest.mark.asyncio
async def test_create_application_unknown_dept_404(client, admin_jwt_headers):
    r = await client.post(BASE, json={"dept_id": str(uuid.uuid4()), "slug": "x", "name": "X"}, headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_application_cross_tenant_dept_404(client, admin_jwt_headers, test_db):
    from db.models import TenantModel
    other = uuid.uuid4()
    test_db.add(TenantModel(id=other, slug=f"t-{other.hex[:8]}", name="O", global_policy={}, is_active=True))
    await test_db.commit()
    did = await _make_dept(test_db, other)          # dept under a foreign tenant
    r = await client.post(BASE, json={"dept_id": did, "slug": "x", "name": "X"}, headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_application_reserved_slug_rejected(client, admin_jwt_headers, test_db):
    # Endpoint-level guard raises the domain ValidationError (INVALID_REQUEST ->
    # 400), distinct from pydantic field validation (422) tested below.
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    r = await client.post(BASE, json={"dept_id": did, "slug": "default", "name": "X"}, headers=admin_jwt_headers)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_create_application_invalid_environment_422(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    r = await client.post(
        BASE,
        json={"dept_id": did, "slug": "envbad", "name": "X", "environment": "prod"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_application_rate_limit_out_of_bounds_422(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    r = await client.post(
        BASE,
        json={"dept_id": did, "slug": "rlbad", "name": "X", "rate_limit_override": 99999},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422


# ── list: full tenant + dept filter ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_applications_filtered_by_dept(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did_a = await _make_dept(test_db, tid)
    did_b = await _make_dept(test_db, tid)
    aid_a = await _create_app(client, admin_jwt_headers, did_a, slug="in-a")
    await _create_app(client, admin_jwt_headers, did_b, slug="in-b")

    r = await client.get(f"{BASE}?dept_id={did_a}", headers=admin_jwt_headers)
    assert r.status_code == 200
    ids = {a["id"] for a in r.json()["applications"]}
    assert aid_a in ids
    assert all(a["dept_id"] == did_a for a in r.json()["applications"])


# ── get + masking ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_application_masks_encrypted_override_key(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    enc = encrypt("sk-app-secret-999", get_settings().secret_key)
    aid = await _seed_app(test_db, tid, did, policy_override={"llm": {"provider": "openai", "api_key_enc": enc}})

    r = await client.get(f"{BASE}/{aid}", headers=admin_jwt_headers)
    assert r.status_code == 200
    llm = r.json()["policy_override"]["llm"]
    assert "api_key_enc" not in llm
    assert llm["api_key_masked"]
    assert "sk-app-secret-999" not in r.text


@pytest.mark.asyncio
async def test_get_application_nonexistent_404(client, admin_jwt_headers):
    r = await client.get(f"{BASE}/{uuid.uuid4()}", headers=admin_jwt_headers)
    assert r.status_code == 404


# ── update (partial + env validation + admin event) ──────────────────────────

@pytest.mark.asyncio
async def test_update_application_fields(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="upd")
    r = await client.put(
        f"{BASE}/{aid}",
        json={"name": "Renamed", "environment": "staging", "metadata": {"team": "core"}},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["name"] == "Renamed"
    assert d["environment"] == "staging"
    assert d["metadata"] == {"team": "core"}


@pytest.mark.asyncio
async def test_update_application_invalid_environment_422(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="upd-env")
    r = await client.put(f"{BASE}/{aid}", json={"environment": "qa"}, headers=admin_jwt_headers)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_update_application_policy_override_admin_event(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="upd-pol")
    # Setting policy_override drives the POLICY_OVERRIDE_CHANGED admin-event path.
    r = await client.put(
        f"{BASE}/{aid}",
        json={"policy_override": {"detection": {"rule_enabled": False}}},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200
    assert r.json()["policy_override"]["detection"]["rule_enabled"] is False


@pytest.mark.asyncio
async def test_update_application_nonexistent_404(client, admin_jwt_headers):
    r = await client.put(f"{BASE}/{uuid.uuid4()}", json={"name": "X"}, headers=admin_jwt_headers)
    assert r.status_code == 404


# ── soft delete ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_application_soft_deletes(client, admin_jwt_headers, test_db):
    from db.models import ApplicationModel
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="to-del")
    r = await client.delete(f"{BASE}/{aid}", headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["deactivated"] is True
    # Row retained for audit history but marked inactive ...
    row = await test_db.get(ApplicationModel, uuid.UUID(aid))
    assert row is not None and row.is_active is False
    # ... and the active-scoped read no longer serves it.
    g = await client.get(f"{BASE}/{aid}", headers=admin_jwt_headers)
    assert g.status_code == 404


@pytest.mark.asyncio
async def test_delete_application_nonexistent_404(client, admin_jwt_headers):
    r = await client.delete(f"{BASE}/{uuid.uuid4()}", headers=admin_jwt_headers)
    assert r.status_code == 404


# ── effective policy: get / set / reset ──────────────────────────────────────

@pytest.mark.asyncio
async def test_get_application_policy_no_override(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="pol-none")
    r = await client.get(f"{BASE}/{aid}/policy", headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["override_set"] is False
    assert "resolved_policy" in r.json()


@pytest.mark.asyncio
async def test_application_policy_override_ssrf_base_url_rejected(client, admin_jwt_headers, test_db):
    # C2: SSRF-validate base_urls in the generic policy_override on update.
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="ssrf-app")
    r = await client.put(
        f"{BASE}/{aid}",
        json={"policy_override": {"llm": {"base_url": "http://169.254.169.254/"}}},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_set_application_policy_resolves_override(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="pol-set")
    r = await client.put(
        f"{BASE}/{aid}/policy",
        json={"policy_override": {"thresholds": {"block": 0.9}}},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["updated"] is True
    assert d["policy_source"] == "application_override"
    assert d["resolved_policy"]["thresholds"]["block"] == 0.9


@pytest.mark.asyncio
async def test_reset_application_policy(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _seed_app(test_db, tid, did, policy_override={"thresholds": {"block": 0.9}})
    r = await client.delete(f"{BASE}/{aid}/policy", headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["reset"] is True
    assert r.json()["policy_override"] is None
    # Confirm it now inherits (override cleared).
    g = await client.get(f"{BASE}/{aid}/policy", headers=admin_jwt_headers)
    assert g.json()["override_set"] is False


# ── LLM override PATCH ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_app_llm_override_set_encrypts_and_masks(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="llm-set")
    r = await client.patch(
        f"{BASE}/{aid}/policy/llm",
        json={"provider": "openai", "model": "gpt-4o", "api_key": "sk-app-llm-plain"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200, r.text
    llm = r.json()["policy_override"]["llm"]
    assert llm["provider"] == "openai"
    assert llm["api_key_masked"]
    assert "api_key_enc" not in llm
    assert "sk-app-llm-plain" not in r.text


@pytest.mark.asyncio
async def test_app_llm_override_clear(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="llm-clr")
    await client.patch(f"{BASE}/{aid}/policy/llm", json={"provider": "openai"}, headers=admin_jwt_headers)
    r = await client.patch(f"{BASE}/{aid}/policy/llm", json={"clear": True}, headers=admin_jwt_headers)
    assert r.status_code == 200
    assert "llm" not in (r.json()["policy_override"] or {})


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"provider": "bogus"},
    {"timeout": 3},
    {"base_url": "http://169.254.169.254/latest"},
])
async def test_app_llm_override_validation_422(client, admin_jwt_headers, test_db, payload):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug=f"llm-bad-{uuid.uuid4().hex[:6]}")
    r = await client.patch(f"{BASE}/{aid}/policy/llm", json=payload, headers=admin_jwt_headers)
    assert r.status_code == 422


# ── proxy override PATCH ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_app_proxy_override_set_encrypts_and_masks(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="prx-set")
    r = await client.patch(
        f"{BASE}/{aid}/policy/proxy",
        json={"provider": "openai", "default_model": "gpt-4o", "api_key": "sk-app-proxy-plain"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200, r.text
    pp = r.json()["policy_override"]["proxy_provider"]
    assert pp["provider"] == "openai"
    assert pp["api_key_masked"]
    assert "api_key_enc" not in pp
    assert "sk-app-proxy-plain" not in r.text


@pytest.mark.asyncio
async def test_app_proxy_override_clear(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="prx-clr")
    await client.patch(f"{BASE}/{aid}/policy/proxy", json={"provider": "openai"}, headers=admin_jwt_headers)
    r = await client.patch(f"{BASE}/{aid}/policy/proxy", json={"clear": True}, headers=admin_jwt_headers)
    assert r.status_code == 200
    assert "proxy_provider" not in (r.json()["policy_override"] or {})


@pytest.mark.asyncio
async def test_app_proxy_override_invalid_timeout_422(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _make_dept(test_db, tid)
    aid = await _create_app(client, admin_jwt_headers, did, slug="prx-bad")
    r = await client.patch(f"{BASE}/{aid}/policy/proxy", json={"timeout_seconds": 999}, headers=admin_jwt_headers)
    assert r.status_code == 422
