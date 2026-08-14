# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Issue 162 regression: HTTP-boundary cross-tenant isolation.

Repo-layer tests live in tests/unit/db/repositories/test_cross_tenant_isolation.py
and prove that every tenant-scoped repository method filters by tenant_id.
These tests exercise the same guarantee at the HTTP layer: a request
authenticated as tenant A's admin must never access tenant B's resource by
ID via any endpoint.

Expected response for cross-tenant lookup is 404 (masking) rather than 403,
so probing for existence does not leak the fact that another tenant owns
the ID.
"""
import uuid

import pytest

# ── API Keys ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_key_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/keys/{b['api_key_id']}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_key_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.put(
        f"/v1/keys/{b['api_key_id']}",
        json={"name": "hijacked"},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_key_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.delete(
        f"/v1/keys/{b['api_key_id']}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_rotate_key_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.post(
        f"/v1/keys/{b['api_key_id']}/rotate",
        json={},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_keys_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/keys",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    key_ids = {k["key_id"] for k in response.json().get("keys", [])}
    assert a["api_key_id"] in key_ids
    assert b["api_key_id"] not in key_ids


# ── Departments ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_department_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/departments/{b['dept'].id}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_department_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.put(
        f"/v1/admin/departments/{b['dept'].id}",
        json={"name": "hijacked"},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_department_stats_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/departments/{b['dept'].id}/stats",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_department_policy_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/departments/{b['dept'].id}/policy",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_departments_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/admin/departments",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    dept_ids = {d["id"] for d in response.json().get("departments", [])}
    assert str(a["dept"].id) in dept_ids
    assert str(b["dept"].id) not in dept_ids


# ── Applications ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_application_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/applications/{b['app'].id}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_application_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.put(
        f"/v1/admin/applications/{b['app'].id}",
        json={"name": "hijacked"},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_application_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.delete(
        f"/v1/admin/applications/{b['app'].id}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_application_policy_get_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/applications/{b['app'].id}/policy",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_application_policy_put_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.put(
        f"/v1/admin/applications/{b['app'].id}/policy",
        json={"policy_override": {}},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_applications_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/admin/applications",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    app_ids = {app["id"] for app in response.json().get("applications", [])}
    assert str(a["app"].id) in app_ids
    assert str(b["app"].id) not in app_ids


# ── Users (admin endpoints) ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_user_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/users/{b['admin_user'].id}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_patch_user_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.patch(
        f"/v1/admin/users/{b['admin_user'].id}",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_users_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/admin/users",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    user_ids = {u["id"] for u in response.json().get("users", [])}
    assert str(a["admin_user"].id) in user_ids
    assert str(b["admin_user"].id) not in user_ids


# ── Audit trace-id lookup (ai.py /v1/ai/requests/{trace_id}) ────────────────

@pytest.mark.asyncio
async def test_get_request_by_trace_cross_tenant_returns_404(auth_client, two_tenant_setup):
    """
    /v1/ai/requests/{trace_id} routes through get_scoped_audit_record. An admin
    of tenant A must not be able to fetch tenant B's audit record by trace_id.
    """
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/ai/requests/{b['audit_trace']}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


# ── Audit Logs ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_logs_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/audit/logs",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json().get("items", [])}
    assert a["audit_trace"] in trace_ids
    assert b["audit_trace"] not in trace_ids


# ── Settings (tenant_settings) ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_settings_scoped_to_own_tenant(auth_client, two_tenant_setup):
    """A tenant admin's settings change (tenant_settings, D5) is invisible to
    another tenant -- proving the two-table split isolates per tenant."""
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]

    ra = await auth_client.put(
        "/v1/settings/thresholds",
        json={"block_threshold": 0.91, "sanitize_threshold": 0.11},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert ra.status_code == 200

    # A sees its own value ...
    ga = await auth_client.get(
        "/v1/settings/thresholds", headers={"Authorization": f"Bearer {a['admin_token']}"}
    )
    assert ga.json()["block_threshold"] == 0.91
    # ... B does not (still the system default, never A's value).
    gb = await auth_client.get(
        "/v1/settings/thresholds", headers={"Authorization": f"Bearer {b['admin_token']}"}
    )
    assert gb.status_code == 200
    assert gb.json()["block_threshold"] != 0.91


# ── Nonexistent-ID sanity check ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nonexistent_ids_also_return_404(auth_client, two_tenant_setup):
    """
    Sanity check that a random UUID returns 404 the same way a cross-tenant
    UUID does. This confirms the guard is masking, not distinguishing between
    "does not exist" and "belongs to another tenant".
    """
    a = two_tenant_setup["A"]
    fake = uuid.uuid4()
    for path in (
        f"/v1/departments/{fake}",
        f"/v1/applications/{fake}",
        f"/v1/admin/users/{fake}",
    ):
        response = await auth_client.get(
            path,
            headers={"Authorization": f"Bearer {a['admin_token']}"},
        )
        assert response.status_code == 404, f"{path} returned {response.status_code}"


# ── Webhooks (v1.3.0) ────────────────────────────────────────────────────────

async def _create_webhook_for(auth_client, tok: str) -> str:
    resp = await auth_client.post(
        "/v1/admin/webhooks",
        json={"url": "https://example.com/hook"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code in (200, 201), f"webhook create failed: {resp.status_code} {resp.text}"
    body = resp.json()
    return body.get("id") or body["endpoint_id"]


@pytest.mark.asyncio
async def test_delete_webhook_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    wid = await _create_webhook_for(auth_client, b["admin_token"])
    # Tenant A's admin must not delete tenant B's webhook.
    resp = await auth_client.delete(
        f"/v1/admin/webhooks/{wid}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert resp.status_code == 404
    # Cleanup as the owner.
    await auth_client.delete(
        f"/v1/admin/webhooks/{wid}",
        headers={"Authorization": f"Bearer {b['admin_token']}"},
    )


@pytest.mark.asyncio
async def test_pause_webhook_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    wid = await _create_webhook_for(auth_client, b["admin_token"])
    resp = await auth_client.post(
        f"/v1/admin/webhooks/{wid}/pause",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert resp.status_code == 404
    await auth_client.delete(
        f"/v1/admin/webhooks/{wid}",
        headers={"Authorization": f"Bearer {b['admin_token']}"},
    )


# ── Tenant profile (H1) ──────────────────────────────────────────────────────
# GET/PUT /v1/admin/tenant must resolve the caller's own tenant, not a fixed
# 'default' tenant -- otherwise any tenant admin reads/writes the default
# tenant's profile and global_policy.

@pytest.mark.asyncio
async def test_get_tenant_profile_scoped_to_caller(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    ra = await auth_client.get("/v1/admin/tenant", headers={"Authorization": f"Bearer {a['admin_token']}"})
    rb = await auth_client.get("/v1/admin/tenant", headers={"Authorization": f"Bearer {b['admin_token']}"})
    assert ra.status_code == 200 and rb.status_code == 200
    # Each admin sees their OWN tenant, not a shared default one.
    assert ra.json()["id"] == str(a["tenant"].id)
    assert rb.json()["id"] == str(b["tenant"].id)
    assert ra.json()["id"] != rb.json()["id"]


@pytest.mark.asyncio
async def test_update_tenant_profile_scoped_to_caller(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    # Tenant B's admin renames B's tenant ...
    upd = await auth_client.put(
        "/v1/admin/tenant",
        json={"name": "Renamed-By-B"},
        headers={"Authorization": f"Bearer {b['admin_token']}"},
    )
    assert upd.status_code == 200
    assert upd.json()["id"] == str(b["tenant"].id)
    assert upd.json()["name"] == "Renamed-By-B"
    # ... and tenant A's profile is untouched (B could not reach it).
    ra = await auth_client.get("/v1/admin/tenant", headers={"Authorization": f"Bearer {a['admin_token']}"})
    assert ra.json()["id"] == str(a["tenant"].id)
    assert ra.json()["name"] != "Renamed-By-B"


# ── The multi-membership edge (D2 Option B's reason to exist) ─────────────────

def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _token(user_id, tenant_id, role, dept_id) -> str:
    """Mint an access token for one user scoped to one membership. The middleware
    re-reads role/dept from the DB membership, so these claims only select which
    membership the session is for."""
    from unittest.mock import MagicMock

    from services.auth.token import create_access_token
    u = MagicMock(); u.id = user_id; u.token_version = 1
    m = MagicMock(); m.tenant_id = tenant_id; m.role = role; m.dept_id = dept_id
    return create_access_token(u, m)


@pytest.mark.asyncio
async def test_one_user_two_memberships_is_token_scoped_with_independent_roles(
    auth_client, two_tenant_setup
):
    """The sharpest edge of D2 Option B: ONE human holding memberships in both
    tenants. A token is scoped to a single membership -- it sees only that tenant,
    and its role is that membership's role. ADMIN in A must not confer admin in B,
    and neither token can reach the other tenant's data. (Everything else tested
    uses different humans per tenant -- the pre-membership threat model.)"""
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )
    from sqlalchemy.pool import NullPool

    from config.settings import get_settings
    from db.repositories.membership import MembershipRepository

    settings = get_settings()
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    user_id  = a["admin_user"].id     # already ADMIN in tenant A (fixture)
    tenant_a = a["tenant"].id
    tenant_b = b["tenant"].id
    dept_b   = b["dept"].id

    # Give A's admin a SECOND membership: VIEWER in tenant B.
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with sf() as db:
            await MembershipRepository(db).upsert_for_user(user_id, tenant_b, "VIEWER", dept_b)
            await db.commit()

        token_a = _token(user_id, tenant_a, "ADMIN",  None)    # session in A
        # The B token carries a FORGED role claim (ADMIN) even though the DB
        # membership is VIEWER. Deliberate: if the middleware ever trusted the
        # token's role instead of re-reading the DB membership, assertion 4 would
        # wrongly pass. Forging it pins the actual security property -- the claim
        # only SELECTS the membership; the DB grants the authz.
        token_b = _token(user_id, tenant_b, "ADMIN", None)     # session in B (role claim lies)
        # A tenant the user holds NO membership in -- the cross-tenant boundary
        # itself (middleware rejects: no membership for the token's tenant).
        token_none = _token(user_id, uuid.uuid4(), "ADMIN", None)

        # 1) Same human, two tokens -> two different tenant profiles.
        pa = await auth_client.get("/v1/admin/tenant", headers=_bearer(token_a))
        pb = await auth_client.get("/v1/admin/tenant", headers=_bearer(token_b))
        assert pa.status_code == 200 and pb.status_code == 200
        assert pa.json()["id"] == str(tenant_a)
        assert pb.json()["id"] == str(tenant_b)

        # 2) A token cannot reach the OTHER tenant's resources (either direction),
        #    even though the same user is a member of both.
        assert (await auth_client.get(f"/v1/keys/{b['api_key_id']}", headers=_bearer(token_a))).status_code == 404
        assert (await auth_client.get(f"/v1/keys/{a['api_key_id']}", headers=_bearer(token_b))).status_code == 404

        # 3) List data is scoped to the token's tenant, not the user's union.
        la = await auth_client.get("/v1/audit/logs", headers=_bearer(token_a))
        traces_a = {i["trace_id"] for i in la.json().get("items", [])}
        assert a["audit_trace"] in traces_a and b["audit_trace"] not in traces_a

        # 4) Role independence, FORGED-CLAIM proof: token_b's role claim says ADMIN
        #    but the DB membership is VIEWER. The admin write must still be 403 --
        #    proving authz comes from the DB membership, not the token claim. (A
        #    regression that trusted the claim would turn this 403 into a 200.)
        thresholds = {"block_threshold": 0.8, "sanitize_threshold": 0.2}
        rb = await auth_client.put("/v1/settings/thresholds", json=thresholds, headers=_bearer(token_b))
        assert rb.status_code == 403
        # ... while the same human's A token (genuine ADMIN in A) may admin A.
        ra = await auth_client.put("/v1/settings/thresholds", json=thresholds, headers=_bearer(token_a))
        assert ra.status_code == 200

        # 5) The boundary itself: a token whose tenant the user is not a member of
        #    is rejected outright (401), not merely scoped away from data. This is
        #    the middleware's no-membership-for-tenant check -- the cross-tenant
        #    boundary that the whole membership model rests on.
        rn = await auth_client.get("/v1/admin/tenant", headers=_bearer(token_none))
        assert rn.status_code == 401
    finally:
        # The extra B-membership cascades when the fixture deletes the user by id.
        await engine.dispose()
