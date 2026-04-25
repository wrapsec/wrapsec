"""
Integration tests for JWT auth endpoints.
Fixtures (auth_client, auth_setup) auto-injected from conftest.py.
Users are created in PostgreSQL so JWT middleware can find them.
"""
import pytest
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
    """Same error message for wrong email and wrong password — no enumeration."""
    response = await auth_client.post(
        "/v1/auth/login",
        json={"email": "nonexistent-xyz@test.com", "password": "TestPass1!"},
    )
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "INVALID_CREDENTIALS"
    assert data["error"]["message"] == "Invalid email or password"


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
    """/me requires JWT — API key must be rejected with 403."""
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
    from db.session import AsyncSessionFactory
    from db.repositories.user import UserRepository
    from services.auth.password import hash_password, normalize_email
    from services.auth.token import create_access_token
    from db.models import UserModel
    from sqlalchemy import delete as sa_delete

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
    from db.session import AsyncSessionFactory
    from db.repositories.user import UserRepository
    from services.auth.password import hash_password, normalize_email
    from services.auth.token import create_access_token
    from db.models import UserModel, RefreshTokenModel
    from sqlalchemy import delete as sa_delete

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
