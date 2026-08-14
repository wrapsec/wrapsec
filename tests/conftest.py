# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import os

os.environ["TESTING"] = "true"
# Runtime posture defaults to production (safe) when unset; the test suite runs
# as development explicitly (drop/create tables, docs enabled), matching the
# pre-migration behavior. setdefault so an explicit override still wins.
os.environ.setdefault("ENVIRONMENT", "development")

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.main import app
from api.v1.dependencies.db import get_db
from config.settings import get_settings
from db.models import Base

settings = get_settings()


# The autouse PostgreSQL bootstrap fixture that previously lived here has
# been moved to tests/integration/conftest.py (see pentest H10). Unit tests
# must not require a live database - autouse at this tier meant every unit
# test errored with ConnectionRefusedError when Docker DB was down.

# ── SQLite - for tests that don't need JWT/users ──────────────────────────────
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"


@pytest_asyncio.fixture(scope="function")
async def test_db():
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def client(test_db):
    async def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport = ASGITransport(app=app),
        base_url  = "http://test",
    ) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture
def admin_headers():
    return {"x-api-key": settings.admin_api_key}


@pytest.fixture
def standard_headers():
    return {"x-api-key": "wsk_live_test_standard_key"}


# ── Session factory for JWT fixtures ─────────────────────────────────────────
# Use the same AsyncSessionFactory the app uses - guarantees insert and login
# hit the exact same database. Creating a separate NullPool engine risks
# connecting to a different DB if settings.database_url varies by context.

def _pg_session_factory():
    from db.session import AsyncSessionFactory
    return AsyncSessionFactory


# ── admin_jwt_headers - uses PostgreSQL, cleans up after itself ───────────────

@pytest_asyncio.fixture
async def admin_jwt_headers():
    """
    Creates a real admin user in PostgreSQL and generates a valid JWT token
    using create_access_token directly - no login endpoint call.

    Why direct token generation (not login endpoint):
        Tests using admin_jwt_headers also use the `client` fixture, which
        sets app.dependency_overrides[get_db] to SQLite. If we call the login
        endpoint here, get_db is overridden to SQLite and the user is not found.
        Direct token generation bypasses this. The token is real and signed,
        goes through the full JWT middleware on subsequent requests, and properly
        tests the auth protection on the PUT endpoints being tested.

    Cleanup: removes the test user after the test completes.
    """
    from sqlalchemy import delete as sa_delete

    from db.models import AdminEventModel, RefreshTokenModel, UserModel
    from db.repositories.tenant import TenantRepository
    from services.auth.password import hash_password, normalize_email
    from services.auth.token import create_access_token

    test_user_id = uuid.uuid4()
    test_email   = normalize_email(f"testadmin-{test_user_id.hex[:8]}@wrapsec-test.com")

    sf = _pg_session_factory()

    async with sf() as db:
        tenant = await TenantRepository(db).get_default()
        assert tenant is not None, "No default tenant found"
        tenant_id = tenant.id

    async with sf() as db:
        user = UserModel(
            id                    = test_user_id,
            tenant_id             = tenant_id,
            dept_id               = None,
            email                 = test_email,
            password_hash         = hash_password("TestAdmin1!"),
            role                  = "ADMIN",
            is_active             = True,
            force_password_change = False,
            token_version         = 1,
        )
        db.add(user)
        await db.flush()
        from db.repositories.membership import MembershipRepository
        membership = await MembershipRepository(db).upsert_for_user(
            test_user_id, tenant_id, "ADMIN", None
        )
        await db.commit()
        # Generate real signed JWT scoped to the membership (session still open).
        token = create_access_token(user, membership)

    yield {"Authorization": f"Bearer {token}"}

    # Cleanup. admin_events.actor_user_id/target_user_id -> users has no
    # ON DELETE CASCADE, so clear those rows before the user (real PG enforces
    # this FK; SQLite did not). auth_events cascades on its own.
    async with sf() as db:
        await db.execute(sa_delete(AdminEventModel).where(
            (AdminEventModel.actor_user_id == test_user_id)
            | (AdminEventModel.target_user_id == test_user_id)
        ))
        await db.execute(sa_delete(RefreshTokenModel).where(RefreshTokenModel.user_id == test_user_id))
        await db.execute(sa_delete(UserModel).where(UserModel.id == test_user_id))
        await db.commit()


# ── auth_setup + auth_client - for test_rbac.py ──────────────────────────────

@pytest_asyncio.fixture(scope="function")
async def auth_setup():
    """
    Creates a complete auth environment in PostgreSQL for RBAC tests:
      - Uses the existing default tenant (avoids FK violation)
      - Creates a department scoped to that tenant
      - Creates Admin, Developer, and Viewer users
      - Generates JWT tokens for each

    All created rows are cleaned up after the test function completes.
    """
    from sqlalchemy import delete as sa_delete

    from db.models import (
        AdminEventModel,
        AuthEventModel,
        DepartmentModel,
        RefreshTokenModel,
        UserModel,
    )
    from db.repositories.tenant import TenantRepository
    from services.auth.password import hash_password, normalize_email
    from services.auth.token import create_access_token

    run_id    = uuid.uuid4().hex[:8]
    dept_id   = uuid.uuid4()
    admin_id  = uuid.uuid4()
    dev_id    = uuid.uuid4()
    viewer_id = uuid.uuid4()

    sf = _pg_session_factory()

    # Use existing default tenant
    async with sf() as db:
        tenant = await TenantRepository(db).get_default()
        assert tenant is not None, "No default tenant found in DB"
        tenant_id = tenant.id

    async with sf() as db:
        dept = DepartmentModel(
            id        = dept_id,
            tenant_id = tenant_id,
            name      = f"rbac-test-dept-{run_id}",
            slug      = f"rbac-test-dept-{run_id}",
        )
        db.add(dept)
        await db.flush()

        admin_user = UserModel(
            id=admin_id, tenant_id=tenant_id, dept_id=None,
            email=normalize_email(f"admin-{run_id}@rbac-test.com"),
            password_hash=hash_password("TestPass1!"),
            role="ADMIN", is_active=True,
            force_password_change=False, token_version=1,
        )
        dev_user = UserModel(
            id=dev_id, tenant_id=tenant_id, dept_id=dept_id,
            email=normalize_email(f"dev-{run_id}@rbac-test.com"),
            password_hash=hash_password("TestPass1!"),
            role="DEVELOPER", is_active=True,
            force_password_change=False, token_version=1,
        )
        viewer_user = UserModel(
            id=viewer_id, tenant_id=tenant_id, dept_id=dept_id,
            email=normalize_email(f"viewer-{run_id}@rbac-test.com"),
            password_hash=hash_password("TestPass1!"),
            role="VIEWER", is_active=True,
            force_password_change=False, token_version=1,
        )
        db.add_all([admin_user, dev_user, viewer_user])
        await db.commit()
        await db.refresh(admin_user)
        await db.refresh(dev_user)
        await db.refresh(viewer_user)
        await db.refresh(dept)

    admin_token  = create_access_token(admin_user)
    dev_token    = create_access_token(dev_user)
    viewer_token = create_access_token(viewer_user)

    yield {
        "tenant":       tenant,
        "dept":         dept,
        "admin_user":   admin_user,
        "dev_user":     dev_user,
        "viewer_user":  viewer_user,
        "admin_token":  admin_token,
        "dev_token":    dev_token,
        "viewer_token": viewer_token,
    }

    # Cleanup in dependency order
    all_user_ids = [admin_id, dev_id, viewer_id]
    async with sf() as db:
        await db.execute(sa_delete(RefreshTokenModel).where(
            RefreshTokenModel.user_id.in_(all_user_ids)))
        await db.execute(sa_delete(AdminEventModel).where(
            AdminEventModel.target_user_id.in_(all_user_ids)))
        await db.execute(sa_delete(AuthEventModel).where(
            AuthEventModel.user_id.in_(all_user_ids)))
        await db.execute(sa_delete(UserModel).where(
            UserModel.id.in_(all_user_ids)))
        await db.execute(sa_delete(DepartmentModel).where(
            DepartmentModel.id == dept_id))
        await db.commit()


@pytest_asyncio.fixture(scope="function")
async def auth_client():
    """
    HTTP client for JWT/RBAC tests.
    Does NOT override get_db - uses the real PostgreSQL database
    so the auth middleware can look up users by UUID.
    """
    async with AsyncClient(
        transport = ASGITransport(app=app),
        base_url  = "http://test",
    ) as c:
        yield c
