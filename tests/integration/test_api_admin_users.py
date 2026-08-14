# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration coverage for the admin user-management endpoints (/v1/admin/users).

RBAC (who may call), basic create/list/get, duplicate-email, weak-password, and
cross-tenant 404 are covered in test_rbac / test_rbac_role_matrix /
test_cross_tenant_isolation. This file targets the branch logic those do not:
role+dept consistency on create/patch, the self-deactivation and last-admin
guards, successful role / active-state transitions, and admin password reset.

Uses auth_client + auth_setup (real PG, one tenant with admin/dev/viewer and
signed tokens), matching the existing user-endpoint tests.
"""

import uuid

import pytest


def _admin(auth_setup) -> dict:
    return {"Authorization": f"Bearer {auth_setup['admin_token']}"}


def _email() -> str:
    return f"newuser-{uuid.uuid4().hex[:10]}@test.com"


# ── create: role + dept consistency and field validation ─────────────────────

@pytest.mark.asyncio
async def test_create_user_invalid_role_400(auth_client, auth_setup):
    r = await auth_client.post(
        "/v1/admin/users",
        json={"email": _email(), "password": "ValidPass123!", "role": "SUPERUSER"},
        headers=_admin(auth_setup),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_create_admin_with_dept_rejected_400(auth_client, auth_setup):
    r = await auth_client.post(
        "/v1/admin/users",
        json={"email": _email(), "password": "ValidPass123!", "role": "ADMIN",
              "dept_id": str(auth_setup["dept"].id)},
        headers=_admin(auth_setup),
    )
    assert r.status_code == 400
    assert "ADMIN" in r.json()["error"]["message"]


@pytest.mark.asyncio
async def test_create_developer_without_dept_400(auth_client, auth_setup):
    r = await auth_client.post(
        "/v1/admin/users",
        json={"email": _email(), "password": "ValidPass123!", "role": "DEVELOPER"},
        headers=_admin(auth_setup),
    )
    assert r.status_code == 400
    assert "dept_id is required" in r.json()["error"]["message"]


@pytest.mark.asyncio
async def test_create_auditor_without_dept_allowed(auth_client, auth_setup):
    # AUDITOR is the one non-admin role permitted to be tenant-wide (dept_id null).
    r = await auth_client.post(
        "/v1/admin/users",
        json={"email": _email(), "password": "ValidPass123!", "role": "AUDITOR"},
        headers=_admin(auth_setup),
    )
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["role"] == "AUDITOR"
    assert d["dept_id"] is None
    assert d["force_password_change"] is True   # always forced on admin-created users


@pytest.mark.asyncio
async def test_create_user_invalid_dept_uuid_400(auth_client, auth_setup):
    r = await auth_client.post(
        "/v1/admin/users",
        json={"email": _email(), "password": "ValidPass123!", "role": "DEVELOPER", "dept_id": "not-a-uuid"},
        headers=_admin(auth_setup),
    )
    assert r.status_code == 400
    assert "UUID" in r.json()["error"]["message"]


# ── list: filters ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_users_filter_by_role(auth_client, auth_setup):
    r = await auth_client.get("/v1/admin/users?role=DEVELOPER", headers=_admin(auth_setup))
    assert r.status_code == 200
    assert {u["role"] for u in r.json()["users"]} == {"DEVELOPER"}


@pytest.mark.asyncio
async def test_list_users_filter_by_is_active(auth_client, auth_setup):
    r = await auth_client.get("/v1/admin/users?is_active=true", headers=_admin(auth_setup))
    assert r.status_code == 200
    assert all(u["is_active"] for u in r.json()["users"])


# ── patch: validation, guards, transitions ───────────────────────────────────

@pytest.mark.asyncio
async def test_patch_user_empty_body_returns_unchanged(auth_client, auth_setup):
    uid = auth_setup["dev_user"].id
    r = await auth_client.patch(f"/v1/admin/users/{uid}", json={}, headers=_admin(auth_setup))
    assert r.status_code == 200
    assert r.json()["role"] == "DEVELOPER"


@pytest.mark.asyncio
async def test_patch_user_invalid_role_400(auth_client, auth_setup):
    uid = auth_setup["dev_user"].id
    r = await auth_client.patch(f"/v1/admin/users/{uid}", json={"role": "KING"}, headers=_admin(auth_setup))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_patch_promote_to_admin_keeping_dept_rejected_400(auth_client, auth_setup):
    # Final state ADMIN + dept_id violates the consistency rule.
    uid = auth_setup["dev_user"].id
    r = await auth_client.patch(f"/v1/admin/users/{uid}", json={"role": "ADMIN"}, headers=_admin(auth_setup))
    assert r.status_code == 400
    assert "ADMIN" in r.json()["error"]["message"]


@pytest.mark.asyncio
async def test_patch_self_deactivation_blocked_409(auth_client, auth_setup):
    uid = auth_setup["admin_user"].id
    r = await auth_client.patch(f"/v1/admin/users/{uid}", json={"is_active": False}, headers=_admin(auth_setup))
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "CANNOT_DEACTIVATE_SELF"


@pytest.mark.asyncio
async def test_patch_last_admin_demotion_blocked_409(auth_client, auth_setup):
    # Demoting the only admin (with a dept so consistency passes) trips the
    # last-admin guard rather than leaving the tenant with zero admins.
    uid = auth_setup["admin_user"].id
    r = await auth_client.patch(
        f"/v1/admin/users/{uid}",
        json={"role": "DEVELOPER", "dept_id": str(auth_setup["dept"].id)},
        headers=_admin(auth_setup),
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "LAST_ADMIN"


@pytest.mark.asyncio
async def test_patch_role_change_succeeds(auth_client, auth_setup):
    uid = auth_setup["dev_user"].id
    r = await auth_client.patch(f"/v1/admin/users/{uid}", json={"role": "VIEWER"}, headers=_admin(auth_setup))
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "VIEWER"


@pytest.mark.asyncio
async def test_patch_deactivate_then_reactivate(auth_client, auth_setup):
    uid = auth_setup["viewer_user"].id
    d = await auth_client.patch(f"/v1/admin/users/{uid}", json={"is_active": False}, headers=_admin(auth_setup))
    assert d.status_code == 200
    assert d.json()["is_active"] is False
    r = await auth_client.patch(f"/v1/admin/users/{uid}", json={"is_active": True}, headers=_admin(auth_setup))
    assert r.status_code == 200
    assert r.json()["is_active"] is True


@pytest.mark.asyncio
async def test_patch_invalid_dept_uuid_400(auth_client, auth_setup):
    uid = auth_setup["dev_user"].id
    r = await auth_client.patch(f"/v1/admin/users/{uid}", json={"dept_id": "not-a-uuid"}, headers=_admin(auth_setup))
    assert r.status_code == 400
    assert "UUID" in r.json()["error"]["message"]


# ── reset-password ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reset_password_success(auth_client, auth_setup):
    uid = auth_setup["dev_user"].id
    r = await auth_client.post(
        f"/v1/admin/users/{uid}/reset-password",
        json={"new_password": "BrandNewPass1!"},
        headers=_admin(auth_setup),
    )
    assert r.status_code == 200, r.text
    assert r.json()["user_id"] == str(uid)
    assert "change password" in r.json()["message"].lower()


@pytest.mark.asyncio
async def test_reset_password_weak_400(auth_client, auth_setup):
    uid = auth_setup["dev_user"].id
    r = await auth_client.post(
        f"/v1/admin/users/{uid}/reset-password",
        json={"new_password": "weak"},
        headers=_admin(auth_setup),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_reset_password_nonexistent_404(auth_client, auth_setup):
    r = await auth_client.post(
        f"/v1/admin/users/{uuid.uuid4()}/reset-password",
        json={"new_password": "BrandNewPass1!"},
        headers=_admin(auth_setup),
    )
    assert r.status_code == 404


# ── M4: dept tenant-ownership on create/update ───────────────────────────────

@pytest.mark.asyncio
async def test_create_user_rejects_cross_tenant_dept(auth_client, two_tenant_setup):
    """M4: creating a user with a department from ANOTHER tenant must 404 -- the
    FK guarantees the dept exists, not that it belongs to the caller's tenant."""
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    r = await auth_client.post(
        "/v1/admin/users",
        json={"email": _email(), "password": "ValidPass123!", "role": "DEVELOPER",
              "dept_id": str(b["dept"].id)},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_update_user_rejects_cross_tenant_dept(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    ah = {"Authorization": f"Bearer {a['admin_token']}"}
    c = await auth_client.post(
        "/v1/admin/users",
        json={"email": _email(), "password": "ValidPass123!", "role": "DEVELOPER",
              "dept_id": str(a["dept"].id)},
        headers=ah,
    )
    assert c.status_code == 201, c.text
    uid = c.json()["id"]
    r = await auth_client.patch(
        f"/v1/admin/users/{uid}",
        json={"dept_id": str(b["dept"].id)},   # move to another tenant's dept
        headers=ah,
    )
    assert r.status_code == 404
