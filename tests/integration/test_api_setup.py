# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration coverage for the first-run setup endpoints (/v1/setup/status, POST
/v1/setup). These operate on the session-seeded default tenant (slug=default),
which starts with zero users. Because users are preserved across tests (not
truncated), each test here resets the default tenant's user set and the Redis
'initialized' cache before and after, so the initialized/uninitialized state is
deterministic and nothing leaks to other tests.
"""

import uuid

import pytest
from sqlalchemy import delete, select

from db.models import AdminEventModel, RefreshTokenModel, TenantModel, UserModel


async def _default_tenant_id(test_db) -> uuid.UUID:
    r = await test_db.execute(select(TenantModel).where(TenantModel.slug == "default"))
    return r.scalar_one().id


async def _clear_setup_cache() -> None:
    try:
        from cache.redis_client import get_redis
        await get_redis().delete("setup:initialized")
    except Exception:
        pass


async def _reset_default_tenant(test_db, tid: uuid.UUID) -> None:
    """Return the default tenant to its pristine zero-user state (FK-safe) and
    clear the Redis initialized flag."""
    user_ids = (await test_db.execute(
        select(UserModel.id).where(UserModel.tenant_id == tid)
    )).scalars().all()
    if user_ids:
        await test_db.execute(delete(RefreshTokenModel).where(RefreshTokenModel.user_id.in_(user_ids)))
        await test_db.execute(delete(AdminEventModel).where(AdminEventModel.tenant_id == tid))
        await test_db.execute(delete(UserModel).where(UserModel.tenant_id == tid))
        await test_db.commit()
    await _clear_setup_cache()


# ── SetupRequest validation (independent of DB state) ────────────────────────

@pytest.mark.asyncio
async def test_setup_rejects_weak_password_422(client):
    r = await client.post("/v1/setup", json={"email": "founder@example.com", "password": "weak"})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_setup_rejects_invalid_email_422(client):
    r = await client.post("/v1/setup", json={"email": "not-an-email", "password": "StrongPass1!"})
    assert r.status_code == 422


# ── status + complete_setup lifecycle ────────────────────────────────────────

@pytest.mark.asyncio
async def test_setup_status_and_first_admin_lifecycle(client, test_db):
    tid = await _default_tenant_id(test_db)
    await _reset_default_tenant(test_db, tid)
    try:
        # Uninitialized: default tenant exists but has no users.
        s = await client.get("/v1/setup/status")
        assert s.status_code == 200
        assert s.json()["initialized"] is False

        # First admin creation succeeds.
        c = await client.post(
            "/v1/setup",
            json={"email": "founder@example.com", "password": "FounderPass1!"},
        )
        assert c.status_code == 201, c.text
        assert "Setup complete" in c.json()["message"]

        # Now initialized: status flips true (Redis warm or DB fallback).
        s2 = await client.get("/v1/setup/status")
        assert s2.json()["initialized"] is True

        # A second setup attempt is indistinguishable from a missing route (404).
        c2 = await client.post(
            "/v1/setup",
            json={"email": "second@example.com", "password": "SecondPass1!"},
        )
        assert c2.status_code == 404
    finally:
        await _reset_default_tenant(test_db, tid)


@pytest.mark.asyncio
async def test_setup_returns_404_when_already_initialized(client, test_db, admin_jwt_headers):
    # admin_jwt_headers guarantees a user in the default tenant, so setup must 404.
    await _clear_setup_cache()
    r = await client.post(
        "/v1/setup",
        json={"email": "late@example.com", "password": "LatePass1!"},
    )
    assert r.status_code == 404

    # With the cache cleared, status takes the DB path (get_default + count > 0)
    # and warms the cache back up.
    s = await client.get("/v1/setup/status")
    assert s.json()["initialized"] is True
    await _clear_setup_cache()
