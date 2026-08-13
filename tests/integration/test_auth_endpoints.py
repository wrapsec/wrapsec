# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for JWT auth endpoints.
Fixtures (auth_client, auth_setup) auto-injected from conftest.py.
Users are created in PostgreSQL so JWT middleware can find them.
"""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from config.settings import get_settings

settings = get_settings()


# ── Login ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_returns_access_token(auth_client, auth_setup):
    email    = auth_setup["admin_user"].email
    response = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 1800
    assert "user" in data


@pytest.mark.asyncio
async def test_login_sets_httponly_cookie(auth_client, auth_setup):
    email    = auth_setup["admin_user"].email
    response = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    assert response.status_code == 200
    assert "refresh_token" in response.cookies


@pytest.mark.asyncio
async def test_login_cookie_secure_flag_matches_setting(auth_client, auth_setup):
    """Set-Cookie Secure attribute must match the cookie_secure setting in both directions."""
    email    = auth_setup["admin_user"].email
    response = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    if settings.cookie_secure:
        assert "secure" in set_cookie.lower(), f"Expected Secure flag. Set-Cookie: {set_cookie}"
    else:
        assert "secure" not in set_cookie.lower(), f"Unexpected Secure flag. Set-Cookie: {set_cookie}"


@pytest.mark.asyncio
async def test_login_wrong_password_401(auth_client, auth_setup):
    email    = auth_setup["admin_user"].email
    response = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "WrongPass1!"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_login_wrong_email_same_message(auth_client, auth_setup):
    """Same error message for wrong email and wrong password - no enumeration."""
    response = await auth_client.post(
        "/v1/auth/login",
        json={"email": "nonexistent-xyz@test.com", "password": "TestPass1!"},
    )
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "INVALID_CREDENTIALS"
    assert data["error"]["message"] == "Invalid credentials."


@pytest.mark.asyncio
async def test_login_force_password_change_in_response(auth_client, auth_setup):
    email    = auth_setup["admin_user"].email
    response = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    assert response.status_code == 200
    assert "force_password_change" in response.json()


@pytest.mark.asyncio
async def test_login_invalid_email_format_422(auth_client, auth_setup):
    """Pydantic EmailStr rejects malformed emails before reaching service layer."""
    response = await auth_client.post(
        "/v1/auth/login",
        json={"email": "notanemail", "password": "TestPass1!"},
    )
    assert response.status_code == 422


# ── /me ────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_me_returns_user_data(auth_client, auth_setup):
    token    = auth_setup["admin_token"]
    response = await auth_client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == auth_setup["admin_user"].email
    assert data["role"]  == "ADMIN"
    assert "force_password_change" in data
    assert "last_login_at" in data


@pytest.mark.asyncio
async def test_me_rejected_with_api_key(auth_client, auth_setup):
    """/me requires JWT - API key must be rejected with 403."""
    response = await auth_client.get(
        "/v1/auth/me",
        headers={"x-api-key": settings.admin_api_key},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_me_rejected_without_auth(auth_client, auth_setup):
    response = await auth_client.get("/v1/auth/me")
    assert response.status_code == 401


# ── change-password ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_change_password_success(auth_client, auth_setup):
    token    = auth_setup["dev_token"]
    response = await auth_client.post(
        "/v1/auth/change-password",
        json={"current_password": "TestPass1!", "new_password": "NewPass2026!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "invalidated" in response.json()["message"].lower()


@pytest.mark.asyncio
async def test_change_password_wrong_current_401(auth_client, auth_setup):
    token    = auth_setup["viewer_token"]
    response = await auth_client.post(
        "/v1/auth/change-password",
        json={"current_password": "WrongPass1!", "new_password": "NewPass2026!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_PASSWORD"


@pytest.mark.asyncio
async def test_change_password_weak_new_400(auth_client, auth_setup):
    token    = auth_setup["viewer_token"]
    response = await auth_client.post(
        "/v1/auth/change-password",
        json={"current_password": "TestPass1!", "new_password": "weak"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


# ── force_password_change enforcement ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_force_password_change_blocks_other_endpoints(auth_client, auth_setup):
    """Middleware blocks all endpoints except allowlist when force_password_change=True."""
    import uuid

    from sqlalchemy import delete as sa_delete

    from db.models import UserModel
    from db.repositories.user import UserRepository
    from db.session import AsyncSessionFactory
    from services.auth.password import hash_password, normalize_email
    from services.auth.token import create_access_token

    tenant = auth_setup["tenant"]
    dept   = auth_setup["dept"]

    async with AsyncSessionFactory() as db:
        repo  = UserRepository(db)
        email = normalize_email(f"forced-{uuid.uuid4().hex[:6]}@test.com")
        user  = await repo.create({
            "tenant_id":             tenant.id,
            "dept_id":               dept.id,
            "email":                 email,
            "password_hash":         hash_password("TestPass1!"),
            "role":                  "DEVELOPER",
            "force_password_change": True,
        })
        await db.commit()
        await db.refresh(user)
        token   = create_access_token(user)
        user_id = user.id

    response = await auth_client.get(
        "/v1/audit/logs",
        headers={"Authorization": f"Bearer {token}"},
    )

    # Cleanup
    async with AsyncSessionFactory() as db:
        from db.models import RefreshTokenModel
        await db.execute(sa_delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id))
        await db.execute(sa_delete(UserModel).where(UserModel.id == user_id))
        await db.commit()

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PASSWORD_CHANGE_REQUIRED"


@pytest.mark.asyncio
async def test_force_password_change_allows_me(auth_client, auth_setup):
    import uuid

    from sqlalchemy import delete as sa_delete

    from db.models import RefreshTokenModel, UserModel
    from db.repositories.user import UserRepository
    from db.session import AsyncSessionFactory
    from services.auth.password import hash_password, normalize_email
    from services.auth.token import create_access_token

    tenant = auth_setup["tenant"]
    dept   = auth_setup["dept"]

    async with AsyncSessionFactory() as db:
        repo  = UserRepository(db)
        email = normalize_email(f"forced2-{uuid.uuid4().hex[:6]}@test.com")
        user  = await repo.create({
            "tenant_id":             tenant.id,
            "dept_id":               dept.id,
            "email":                 email,
            "password_hash":         hash_password("TestPass1!"),
            "role":                  "DEVELOPER",
            "force_password_change": True,
        })
        await db.commit()
        await db.refresh(user)
        token   = create_access_token(user)
        user_id = user.id

    response = await auth_client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    async with AsyncSessionFactory() as db:
        await db.execute(sa_delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id))
        await db.execute(sa_delete(UserModel).where(UserModel.id == user_id))
        await db.commit()

    assert response.status_code == 200


# ── logout ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logout_success(auth_client, auth_setup):
    token    = auth_setup["admin_token"]
    response = await auth_client.post(
        "/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Logged out successfully."


@pytest.mark.asyncio
async def test_logout_requires_jwt(auth_client, auth_setup):
    response = await auth_client.post("/v1/auth/logout")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_logout_clears_refresh_cookie(auth_client, auth_setup):
    """Logout must set refresh_token cookie to empty with max-age=0."""
    email    = auth_setup["admin_user"].email
    login_r  = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    assert login_r.status_code == 200
    token    = login_r.json()["access_token"]

    logout_r = await auth_client.post(
        "/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_r.status_code == 200
    set_cookie = logout_r.headers.get("set-cookie", "")
    assert "refresh_token" in set_cookie
    assert "max-age=0" in set_cookie.lower()


# ── Account lockout ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_lockout_after_max_attempts(auth_client, auth_setup):
    """N wrong passwords lock the account - further attempts return 401."""
    email = auth_setup["admin_user"].email
    for _ in range(settings.auth_max_failed_attempts):
        r = await auth_client.post(
            "/v1/auth/login",
            json={"email": email, "password": "WrongPass1!"},
        )
        assert r.status_code == 401

    # Account now locked - correct password still returns 401
    r = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_login_lockout_does_not_leak_locked_status(auth_client, auth_setup):
    """Locked account returns identical message to wrong password - no enumeration."""
    email = auth_setup["dev_user"].email
    for _ in range(settings.auth_max_failed_attempts):
        await auth_client.post(
            "/v1/auth/login",
            json={"email": email, "password": "WrongPass1!"},
        )

    r = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    assert r.status_code == 401
    assert r.json()["error"]["message"] == "Invalid credentials."


@pytest.mark.asyncio
async def test_login_lockout_clears_on_success(auth_client, auth_setup):
    """Failure counter clears after a successful login."""
    email = auth_setup["viewer_user"].email

    # Fail one short of lockout
    for _ in range(settings.auth_max_failed_attempts - 1):
        await auth_client.post(
            "/v1/auth/login",
            json={"email": email, "password": "WrongPass1!"},
        )

    # Successful login - clears the counter
    r = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    assert r.status_code == 200

    # Wrong password again - counter reset, so no lockout yet
    r = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "WrongPass1!"},
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"


# ── Inactive user ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_inactive_user_401(auth_client, auth_setup):
    """Inactive account returns 401 with identical message - no status leak."""
    import uuid

    from sqlalchemy import delete as sa_delete

    from db.models import RefreshTokenModel, UserModel
    from db.repositories.user import UserRepository
    from services.auth.password import hash_password, normalize_email

    tenant = auth_setup["tenant"]
    dept   = auth_setup["dept"]
    email  = normalize_email(f"inactive-{uuid.uuid4().hex[:6]}@test.com")

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf     = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    user_id = None
    try:
        async with sf() as db:
            repo = UserRepository(db)
            u    = await repo.create({
                "tenant_id":             tenant.id,
                "dept_id":               dept.id,
                "email":                 email,
                "password_hash":         hash_password("TestPass1!"),
                "role":                  "VIEWER",
                "force_password_change": False,
                "is_active":             False,
            })
            await db.commit()
            user_id = u.id
    finally:
        await engine.dispose()

    r = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )

    # Cleanup
    engine2 = create_async_engine(settings.database_url, poolclass=NullPool)
    sf2     = async_sessionmaker(bind=engine2, class_=AsyncSession, expire_on_commit=False)
    try:
        async with sf2() as db:
            await db.execute(sa_delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id))
            await db.execute(sa_delete(UserModel).where(UserModel.id == user_id))
            await db.commit()
    finally:
        await engine2.dispose()

    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"
    assert r.json()["error"]["message"] == "Invalid credentials."


# ── Email normalisation ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_case_insensitive_email(auth_client, auth_setup):
    """Login with uppercase email must succeed - email is normalised before lookup."""
    email_lower = auth_setup["admin_user"].email
    email_upper = email_lower.upper()
    r = await auth_client.post(
        "/v1/auth/login",
        json={"email": email_upper, "password": "TestPass1!"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_login_email_whitespace_stripped(auth_client, auth_setup):
    """Leading/trailing whitespace in email is stripped before lookup."""
    email = auth_setup["admin_user"].email
    r     = await auth_client.post(
        "/v1/auth/login",
        json={"email": f"  {email}  ", "password": "TestPass1!"},
    )
    assert r.status_code == 200


# ── Token refresh ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_returns_new_access_token(auth_client, auth_setup):
    """Refresh with valid cookie returns new access token."""
    email   = auth_setup["admin_user"].email
    login_r = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    assert login_r.status_code == 200
    raw_cookie = login_r.cookies.get("refresh_token")
    assert raw_cookie, "refresh_token cookie missing after login"

    refresh_r = await auth_client.post(
        "/v1/auth/refresh",
        cookies={"refresh_token": raw_cookie},
    )
    assert refresh_r.status_code == 200
    data = refresh_r.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data


@pytest.mark.asyncio
async def test_refresh_rotates_cookie(auth_client, auth_setup):
    """Refresh must set a new refresh_token cookie (token rotation)."""
    email   = auth_setup["dev_user"].email
    login_r = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    raw_cookie = login_r.cookies.get("refresh_token")

    refresh_r = await auth_client.post(
        "/v1/auth/refresh",
        cookies={"refresh_token": raw_cookie},
    )
    assert refresh_r.status_code == 200
    assert "refresh_token" in refresh_r.cookies


@pytest.mark.asyncio
async def test_refresh_old_token_rejected_after_rotation(auth_client, auth_setup):
    """After rotation the original refresh token must be invalid."""
    email   = auth_setup["viewer_user"].email
    login_r = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    raw_cookie = login_r.cookies.get("refresh_token")

    # First refresh - rotates token
    r1 = await auth_client.post(
        "/v1/auth/refresh",
        cookies={"refresh_token": raw_cookie},
    )
    assert r1.status_code == 200

    # Replaying original token must fail
    r2 = await auth_client.post(
        "/v1/auth/refresh",
        cookies={"refresh_token": raw_cookie},
    )
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_refresh_without_cookie_401(auth_client, auth_setup):
    """Refresh with no cookie returns 401."""
    r = await auth_client.post("/v1/auth/refresh")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_TOKEN"


# ── Session invalidation ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_old_token_rejected_after_password_change(auth_client, auth_setup):
    """JWT issued before password change must be rejected after change."""
    email     = auth_setup["dev_user"].email
    login_r   = await auth_client.post(
        "/v1/auth/login",
        json={"email": email, "password": "TestPass1!"},
    )
    old_token = login_r.json()["access_token"]

    # Change password - increments token_version
    await auth_client.post(
        "/v1/auth/change-password",
        json={"current_password": "TestPass1!", "new_password": "NewPass2026!"},
        headers={"Authorization": f"Bearer {old_token}"},
    )

    # Old token must now be rejected
    r = await auth_client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert r.status_code == 401


# ── Admin password reset ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_reset_password_sets_force_change(auth_client, auth_setup):
    """Admin reset must set force_password_change=True and allow login."""
    admin_token = auth_setup["admin_token"]
    target_id   = str(auth_setup["dev_user"].id)
    target_email = auth_setup["dev_user"].email

    r = await auth_client.post(
        f"/v1/admin/users/{target_id}/reset-password",
        json={"new_password": "ResetPass1!"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200

    # Login with new password must succeed
    login_r = await auth_client.post(
        "/v1/auth/login",
        json={"email": target_email, "password": "ResetPass1!"},
    )
    assert login_r.status_code == 200
    assert login_r.json()["force_password_change"] is True


@pytest.mark.asyncio
async def test_admin_reset_invalidates_existing_sessions(auth_client, auth_setup):
    """Sessions active before admin reset must be rejected after."""
    admin_token  = auth_setup["admin_token"]
    target_email = auth_setup["viewer_user"].email
    target_id    = str(auth_setup["viewer_user"].id)

    # Get a valid token for the target user
    login_r = await auth_client.post(
        "/v1/auth/login",
        json={"email": target_email, "password": "TestPass1!"},
    )
    old_token = login_r.json()["access_token"]

    # Admin resets password - invalidates all sessions
    await auth_client.post(
        f"/v1/admin/users/{target_id}/reset-password",
        json={"new_password": "ResetPass1!"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    # Old token must now be rejected
    r = await auth_client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_admin_create_user_sets_force_password_change(auth_client, auth_setup):
    """New users created by admin must have force_password_change=True."""
    import uuid

    from sqlalchemy import delete as sa_delete

    from db.models import RefreshTokenModel, UserModel

    admin_token = auth_setup["admin_token"]
    dept_id     = str(auth_setup["dept"].id)
    new_email   = f"newuser-{uuid.uuid4().hex[:6]}@test.com"

    r = await auth_client.post(
        "/v1/admin/users",
        json={
            "email":    new_email,
            "password": "TempPass1!",
            "role":     "DEVELOPER",
            "dept_id":  dept_id,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["force_password_change"] is True
    new_user_id = uuid.UUID(data["id"])

    # Cleanup
    from db.models import AdminEventModel
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf     = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with sf() as db:
            await db.execute(sa_delete(RefreshTokenModel).where(RefreshTokenModel.user_id == new_user_id))
            await db.execute(sa_delete(AdminEventModel).where(AdminEventModel.target_user_id == new_user_id))
            await db.execute(sa_delete(UserModel).where(UserModel.id == new_user_id))
            await db.commit()
    finally:
        await engine.dispose()
