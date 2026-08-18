# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for RBAC and auth boundary enforcement.
Fixtures (auth_client, auth_setup) auto-injected from conftest.py.
Users are created in PostgreSQL so JWT middleware can find them.
"""
import pytest

from config.settings import get_settings

settings = get_settings()


# ── Header precedence ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_key_wins_when_both_headers_sent(auth_client, auth_setup):
    """x-api-key always wins - JWT is ignored even if valid."""
    token    = auth_setup["admin_token"]
    response = await auth_client.get(
        "/v1/auth/me",
        headers={
            "x-api-key":     settings.admin_api_key,
            "Authorization": f"Bearer {token}",
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_no_auth_returns_401(auth_client, auth_setup):
    response = await auth_client.get("/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_api_key_can_scan(auth_client, auth_setup):
    """API key accepted on scan endpoint (Option B)."""
    response = await auth_client.post(
        "/v1/ai/request",
        json={"input": "hello world"},
        headers={"x-api-key": settings.admin_api_key},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_jwt_developer_can_scan(auth_client, auth_setup):
    """JWT user accepted on scan endpoint (Option B)."""
    token    = auth_setup["dev_token"]
    response = await auth_client.post(
        "/v1/ai/request",
        json={"input": "hello world"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


# ── Role enforcement ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_can_list_users(auth_client, auth_setup):
    token    = auth_setup["admin_token"]
    response = await auth_client.get(
        "/v1/admin/users",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "users" in response.json()


@pytest.mark.asyncio
async def test_developer_cannot_list_users_403(auth_client, auth_setup):
    token    = auth_setup["dev_token"]
    response = await auth_client.get(
        "/v1/admin/users",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_viewer_cannot_list_users_403(auth_client, auth_setup):
    token    = auth_setup["viewer_token"]
    response = await auth_client.get(
        "/v1/admin/users",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_api_key_cannot_access_admin_users_403(auth_client, auth_setup):
    response = await auth_client.get(
        "/v1/admin/users",
        headers={"x-api-key": settings.admin_api_key},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


# ── Tenant isolation ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_sees_only_own_tenant_users(auth_client, auth_setup):
    token    = auth_setup["admin_token"]
    response = await auth_client.get(
        "/v1/admin/users",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    users     = response.json()["users"]
    tenant_id = str(auth_setup["tenant"].id)
    for user in users:
        assert user["tenant_id"] == tenant_id


# ── Session invalidation ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_session_invalidated_after_password_change(auth_client, auth_setup):
    """Old token rejected after password change increments token_version."""
    old_token = auth_setup["viewer_token"]

    await auth_client.post(
        "/v1/auth/change-password",
        json={"current_password": "TestPass1!", "new_password": "NewPass2026!"},
        headers={"Authorization": f"Bearer {old_token}"},
    )

    response = await auth_client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SESSION_INVALIDATED"


# ── User management ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_can_create_user(auth_client, auth_setup):
    import uuid
    token   = auth_setup["admin_token"]
    dept_id = str(auth_setup["dept"].id)

    response = await auth_client.post(
        "/v1/admin/users",
        json={
            "email":    f"newuser-rbac-{uuid.uuid4().hex[:8]}@test.com",
            "password": "NewPass2026!",
            "role":     "DEVELOPER",
            "dept_id":  dept_id,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"].startswith("newuser-rbac-")
    assert data["role"]                  == "DEVELOPER"
    assert data["force_password_change"] is True

    # Cleanup created user
    user_id = data["id"]
    from sqlalchemy import delete as sa_delete

    from db.models import AdminEventModel, RefreshTokenModel, UserModel
    from db.session import AsyncSessionFactory
    async with AsyncSessionFactory() as db:
        import uuid
        uid = uuid.UUID(user_id)
        await db.execute(sa_delete(RefreshTokenModel).where(RefreshTokenModel.user_id == uid))
        await db.execute(sa_delete(AdminEventModel).where(AdminEventModel.target_user_id == uid))
        await db.execute(sa_delete(UserModel).where(UserModel.id == uid))
        await db.commit()


@pytest.mark.asyncio
async def test_create_user_duplicate_email_409(auth_client, auth_setup):
    token   = auth_setup["admin_token"]
    dept_id = str(auth_setup["dept"].id)

    response = await auth_client.post(
        "/v1/admin/users",
        json={
            "email":    auth_setup["admin_user"].email,  # already exists
            "password": "NewPass2026!",
            "role":     "DEVELOPER",
            "dept_id":  dept_id,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_create_user_weak_password_400(auth_client, auth_setup):
    token   = auth_setup["admin_token"]
    dept_id = str(auth_setup["dept"].id)

    response = await auth_client.post(
        "/v1/admin/users",
        json={
            "email":    "weakpass-rbac@test.com",
            "password": "weak",
            "role":     "DEVELOPER",
            "dept_id":  dept_id,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_last_admin_cannot_be_deactivated(auth_client, auth_setup):
    token   = auth_setup["admin_token"]
    user_id = str(auth_setup["admin_user"].id)

    response = await auth_client.patch(
        f"/v1/admin/users/{user_id}",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    # State conflict (409): either the self-deactivation guard or the last-admin
    # guard fires - both are dedicated, stable codes.
    assert response.status_code == 409
    assert response.json()["error"]["code"] in ("CANNOT_DEACTIVATE_SELF", "LAST_ADMIN")


@pytest.mark.asyncio
async def test_get_user_scoped_to_tenant(auth_client, auth_setup):
    token   = auth_setup["admin_token"]
    user_id = str(auth_setup["dev_user"].id)

    response = await auth_client.get(
        f"/v1/admin/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["id"] == user_id


@pytest.mark.asyncio
async def test_get_nonexistent_user_404(auth_client, auth_setup):
    import uuid
    token    = auth_setup["admin_token"]
    response = await auth_client.get(
        f"/v1/admin/users/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


# ── Invalid token scenarios ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tampered_token_401(auth_client, auth_setup):
    token    = auth_setup["admin_token"] + "tampered"
    response = await auth_client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_malformed_bearer_401(auth_client, auth_setup):
    response = await auth_client.get(
        "/v1/auth/me",
        headers={"Authorization": "Bearer notavalidtoken"},
    )
    assert response.status_code == 401
