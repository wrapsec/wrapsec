# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Tenant suspension enforcement fails CLOSED.

`docs/api.md` states that a suspended tenant's credentials return 403 on every
request. The lookup returned False (allow) on any error, so that held only while
Redis and the database were reachable: during a datastore disturbance a
suspended tenant regained access, and nothing in the response or the metrics
said so.

Suspension is an authorization boundary, which is why it fails closed here while
the rate limiter fails open -- exceeding a quota is not a boundary.

The distinction these tests pin: a tenant row that does NOT EXIST is a definite
answer and is not suspended; a lookup that could not be ANSWERED refuses.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from api.v1.middleware.auth import _tenant_suspended

TENANT = "11111111-1111-1111-1111-111111111111"


def _repo_returning(tenant):
    """A TenantRepository whose get_by_id yields `tenant`."""
    repo = SimpleNamespace(get_by_id=AsyncMock(return_value=tenant))
    return lambda _session: repo


def _repo_raising(exc):
    repo = SimpleNamespace(get_by_id=AsyncMock(side_effect=exc))
    return lambda _session: repo


class _Session:
    async def __aenter__(self):
        return self
    async def __aexit__(self, *a):
        return False


def _db_session_ok():
    return AsyncMock(return_value=(None, _Session()))


# ── definite answers ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_active_tenant_is_not_suspended():
    with patch("api.v1.middleware.auth._get_db_session", _db_session_ok()), \
         patch("db.repositories.tenant.TenantRepository",
               _repo_returning(SimpleNamespace(status="active"))):
        assert await _tenant_suspended(TENANT) is False


@pytest.mark.asyncio
async def test_suspended_tenant_is_suspended():
    with patch("api.v1.middleware.auth._get_db_session", _db_session_ok()), \
         patch("db.repositories.tenant.TenantRepository",
               _repo_returning(SimpleNamespace(status="suspended"))):
        assert await _tenant_suspended(TENANT) is True


@pytest.mark.asyncio
async def test_absent_tenant_row_is_not_suspended():
    """
    A row that does not exist is a definite answer, not an unanswerable lookup.
    Other guards reject an unrecognised tenant; failing closed here as well
    would refuse traffic for a condition this function is not the authority on.
    """
    with patch("api.v1.middleware.auth._get_db_session", _db_session_ok()), \
         patch("db.repositories.tenant.TenantRepository", _repo_returning(None)):
        assert await _tenant_suspended(TENANT) is False


@pytest.mark.asyncio
async def test_no_tenant_context_is_not_suspended():
    """The admin-key sentinel carries no tenant; nothing to suspend."""
    assert await _tenant_suspended(None) is False
    assert await _tenant_suspended("") is False


# ── unanswerable lookups: must refuse ────────────────────────────────────────

@pytest.mark.asyncio
async def test_database_error_fails_closed():
    """A lookup that cannot be answered returned False, and the request was
    served -- a suspended tenant regained access whenever the datastore was
    unreachable."""
    with patch("api.v1.middleware.auth._get_db_session", _db_session_ok()), \
         patch("db.repositories.tenant.TenantRepository",
               _repo_raising(RuntimeError("database unreachable"))):
        assert await _tenant_suspended(TENANT) is True, (
            "a tenant whose status cannot be established must not be served"
        )


@pytest.mark.asyncio
async def test_session_acquisition_failure_fails_closed():
    with patch("api.v1.middleware.auth._get_db_session",
               AsyncMock(side_effect=RuntimeError("no connection"))):
        assert await _tenant_suspended(TENANT) is True


@pytest.mark.asyncio
async def test_malformed_tenant_id_fails_closed():
    """
    A tenant_id that is not a UUID cannot be looked up, so its status cannot be
    established. Refusing is the same rule as any other unanswerable lookup.
    """
    with patch("api.v1.middleware.auth._get_db_session", _db_session_ok()), \
         patch("db.repositories.tenant.TenantRepository",
               _repo_returning(SimpleNamespace(status="active"))):
        assert await _tenant_suspended("not-a-uuid") is True


# ── the cache layer must not weaken it ───────────────────────────────────────

@pytest.mark.asyncio
async def test_a_cache_error_alone_falls_through_to_the_database():
    """
    Redis being unavailable is not by itself an unanswerable lookup: the
    database is still authoritative. Only total failure refuses, so a Redis
    blip does not take authenticated traffic down.
    """
    with patch("api.v1.middleware.auth._TESTING", False), \
         patch("cache.redis_client.get_redis",
               side_effect=RuntimeError("redis down")), \
         patch("api.v1.middleware.auth._get_db_session", _db_session_ok()), \
         patch("db.repositories.tenant.TenantRepository",
               _repo_returning(SimpleNamespace(status="active"))):
        assert await _tenant_suspended(TENANT) is False
