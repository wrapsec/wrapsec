# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration test fixtures.
Uses session-scoped event loop.
Flushes rate_limit and auth lockout Redis keys before each auth test
to prevent cross-test accumulation.
"""
import os
os.environ["TESTING"] = "true"

import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import (
    create_async_engine, async_sessionmaker, AsyncSession,
)
from sqlalchemy.pool import NullPool

from api.main import app
from api.v1.dependencies.db import get_db
from db.models import Base
from config.settings import get_settings

settings = get_settings()

# ── Existing fixtures ──────────────────────────────────────────────────────────

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
    # Clear any leftover overrides from previous test
    app.dependency_overrides.clear()

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


# ── Redis helpers ─────────────────────────────────────────────────────────────

async def _flush_test_redis_keys():
    """
    Flushes rate limit and auth lockout Redis keys before auth tests.
    Rate limit key: rate_limit:{ip} - accumulates across tests from 127.0.0.1
    Lockout keys: auth:failed:{email}, auth:locked:{email}

    Uses KEYS - O(N) blocking command. Acceptable for test cleanup on a local
    Redis instance with a small keyspace. Never use KEYS in production code.
    """
    try:
        from cache.redis_client import get_redis
        redis = get_redis()
        patterns = [
            "rate_limit:*",      # rate_limit_store.py pattern
            "auth:failed:*",     # lockout.py pattern
            "auth:locked:*",     # lockout.py pattern
        ]
        keys = []
        for pattern in patterns:
            found = await redis.keys(pattern)
            keys.extend(found)
        if keys:
            await redis.delete(*keys)
    except Exception:
        pass  # Redis unavailable - silently skip


# ── Auth fixtures ──────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="function")
async def auth_client():
    """HTTP client against real app - no DB override."""
    app.dependency_overrides.clear()
    # Flush rate limit keys before each auth test
    await _flush_test_redis_keys()
    async with AsyncClient(
        transport = ASGITransport(app=app),
        base_url  = "http://test",
    ) as c:
        yield c
    app.dependency_overrides.clear()
    await _flush_test_redis_keys()


@pytest_asyncio.fixture(scope="function")
async def auth_setup():
    """
    Creates tenant + dept + users in PostgreSQL using NullPool.
    JWT middleware also uses NullPool in test mode (auth.py _get_db_session).
    Cleans up all DB rows after each test.
    """
    from db.models import TenantModel, DepartmentModel, UserModel, RefreshTokenModel
    from db.repositories.user import UserRepository
    from services.auth.password import hash_password, normalize_email
    from services.auth.token import create_access_token
    from sqlalchemy import delete as sa_delete
    from unittest.mock import MagicMock

    tenant_id     = uuid.uuid4()
    dept_id       = uuid.uuid4()
    slug          = f"test-{uuid.uuid4().hex[:8]}"
    admin_email   = normalize_email(f"admin-{uuid.uuid4().hex[:6]}@test.com")
    dev_email     = normalize_email(f"dev-{uuid.uuid4().hex[:6]}@test.com")
    viewer_email  = normalize_email(f"viewer-{uuid.uuid4().hex[:6]}@test.com")
    password_hash = hash_password("TestPass1!")

    admin_db_id = dev_db_id = viewer_db_id = None

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    try:
        async with sf() as db:
            db.add(TenantModel(id=tenant_id, slug=slug, name="Test Tenant",
                               global_policy={}, is_active=True))
            await db.commit()

            db.add(DepartmentModel(id=dept_id, tenant_id=tenant_id,
                                   slug="engineering", name="Engineering",
                                   is_active=True))
            await db.commit()

            repo = UserRepository(db)

            u = await repo.create({
                "tenant_id": tenant_id, "dept_id": None,
                "email": admin_email, "password_hash": password_hash,
                "role": "ADMIN", "force_password_change": False,
            })
            await db.commit()
            admin_db_id = u.id

            u = await repo.create({
                "tenant_id": tenant_id, "dept_id": dept_id,
                "email": dev_email, "password_hash": password_hash,
                "role": "DEVELOPER", "force_password_change": False,
            })
            await db.commit()
            dev_db_id = u.id

            u = await repo.create({
                "tenant_id": tenant_id, "dept_id": dept_id,
                "email": viewer_email, "password_hash": password_hash,
                "role": "VIEWER", "force_password_change": False,
            })
            await db.commit()
            viewer_db_id = u.id

    finally:
        await engine.dispose()

    def _mock(uid, tid, did, role):
        m = MagicMock()
        m.id = uid; m.tenant_id = tid; m.dept_id = did
        m.role = role; m.token_version = 1
        return m

    class _Obj:
        def __init__(self, **kw): self.__dict__.update(kw)

    yield {
        "tenant":       _Obj(id=tenant_id),
        "dept":         _Obj(id=dept_id),
        "admin_user":   _Obj(id=admin_db_id,  email=admin_email,  role="ADMIN"),
        "admin_token":  create_access_token(_mock(admin_db_id,  tenant_id, None,    "ADMIN")),
        "dev_user":     _Obj(id=dev_db_id,    email=dev_email,    role="DEVELOPER"),
        "dev_token":    create_access_token(_mock(dev_db_id,    tenant_id, dept_id, "DEVELOPER")),
        "viewer_user":  _Obj(id=viewer_db_id, email=viewer_email, role="VIEWER"),
        "viewer_token": create_access_token(_mock(viewer_db_id, tenant_id, dept_id, "VIEWER")),
    }

    # ── Cleanup ────────────────────────────────────────────────────────────────
    engine2 = create_async_engine(settings.database_url, poolclass=NullPool)
    sf2 = async_sessionmaker(bind=engine2, class_=AsyncSession, expire_on_commit=False)
    try:
        async with sf2() as db:
            ids = [i for i in [admin_db_id, dev_db_id, viewer_db_id] if i]
            if ids:
                from sqlalchemy import delete as sa_delete
                await db.execute(sa_delete(RefreshTokenModel).where(
                    RefreshTokenModel.user_id.in_(ids)))
                await db.execute(sa_delete(UserModel).where(
                    UserModel.tenant_id == tenant_id))
            await db.execute(sa_delete(DepartmentModel).where(
                DepartmentModel.id == dept_id))
            await db.execute(sa_delete(TenantModel).where(
                TenantModel.id == tenant_id))
            await db.commit()
    except Exception:
        pass
    finally:
        await engine2.dispose()
