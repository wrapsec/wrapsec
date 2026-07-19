# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
F-5 regression: retention scheduler cross-process lease.

Prior state: workers/queue.py starts an AsyncIOScheduler in every uvicorn
worker, and the cron trigger fires the cleanup job in every worker at 02:00
UTC. The DELETE/UPDATE statements are idempotent so the final state is
correct - but the duplicate DB work is wasted load and grows linearly with
worker count.

Fix: acquire a Redis lease via SET NX PX before running the cleanup. Only
one worker per install per day wins the lease and does the work; the others
log-and-return. Fail-open if Redis is unreachable (worst case reverts to the
pre-fix duplicate-work behavior; never fail-closed as that would skip
cleanup entirely).

These tests pin four properties:
  1. Lease acquisition uses SET with nx=True and a bounded ex TTL.
  2. If the lease is acquired, cleanup proceeds.
  3. If another worker holds the lease, this worker skips cleanup.
  4. If Redis raises, the worker falls through (fail-open).
"""

from unittest.mock import AsyncMock, patch

import pytest

from workers import tasks as tasks_module
from workers.tasks import (
    RETENTION_LEASE_KEY,
    RETENTION_LEASE_TTL,
    _acquire_retention_lease,
    run_retention_cleanup,
)


class _FakeRedis:
    """Minimal redis stub: records the SET call so we can assert kwargs."""

    def __init__(self, acquired: bool = True, raise_on_set: bool = False):
        self._acquired    = acquired
        self._raise       = raise_on_set
        self.set_calls    = []

    async def set(self, key, value, nx=False, ex=None):
        self.set_calls.append({"key": key, "value": value, "nx": nx, "ex": ex})
        if self._raise:
            raise ConnectionError("redis unavailable")
        return self._acquired


# ── _acquire_retention_lease ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_lease_acquired_returns_true():
    """Redis SET NX succeeds - lease is acquired, worker should run."""
    fake = _FakeRedis(acquired=True)
    with patch("cache.redis_client.get_redis", return_value=fake):
        result = await _acquire_retention_lease()
    assert result is True


@pytest.mark.asyncio
async def test_lease_not_acquired_returns_false():
    """Redis SET NX returns None (key already exists) - this worker must skip."""
    fake = _FakeRedis(acquired=False)
    with patch("cache.redis_client.get_redis", return_value=fake):
        result = await _acquire_retention_lease()
    assert result is False


@pytest.mark.asyncio
async def test_lease_uses_nx_and_bounded_ttl():
    """
    The lease MUST be acquired with SET NX (atomic claim) and MUST carry a
    bounded TTL so a crashed worker doesn't block tomorrow's run. A missing
    TTL or nx=False would silently disable the coordination.
    """
    fake = _FakeRedis(acquired=True)
    with patch("cache.redis_client.get_redis", return_value=fake):
        await _acquire_retention_lease()
    assert len(fake.set_calls) == 1
    call = fake.set_calls[0]
    assert call["key"] == RETENTION_LEASE_KEY
    assert call["nx"]  is True
    assert call["ex"]  == RETENTION_LEASE_TTL
    assert RETENTION_LEASE_TTL <= 24 * 3600, (
        "Lease TTL must be less than the daily cadence so a crashed worker "
        "never blocks the next scheduled run."
    )


@pytest.mark.asyncio
async def test_lease_fails_open_on_redis_error():
    """
    If Redis raises, the worker MUST fall through and run. The pre-fix
    behavior was duplicate-work - that's the correct fallback. NEVER
    fail-closed here, that would skip cleanup entirely.
    """
    fake = _FakeRedis(raise_on_set=True)
    with patch("cache.redis_client.get_redis", return_value=fake):
        result = await _acquire_retention_lease()
    assert result is True, "Redis error must not prevent cleanup - fail-open."


# ── run_retention_cleanup gating ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_cleanup_skips_when_lease_denied():
    """
    Full run_retention_cleanup: when the lease is held by another worker,
    none of the _cleanup_* helpers should be called.
    """
    with patch.object(tasks_module, "_acquire_retention_lease", AsyncMock(return_value=False)), \
         patch.object(tasks_module, "_cleanup_audit_logs",         AsyncMock(return_value=0)) as m_audit, \
         patch.object(tasks_module, "_cleanup_proxy_interactions", AsyncMock(return_value=0)) as m_proxy, \
         patch.object(tasks_module, "_cleanup_refresh_tokens",     AsyncMock(return_value=0)) as m_tokens:
        await run_retention_cleanup()

    m_audit.assert_not_called()
    m_proxy.assert_not_called()
    m_tokens.assert_not_called()


@pytest.mark.asyncio
async def test_run_cleanup_proceeds_when_lease_granted():
    """When the lease is acquired, all three cleanup helpers must run."""
    with patch.object(tasks_module, "_acquire_retention_lease", AsyncMock(return_value=True)), \
         patch.object(tasks_module, "_cleanup_audit_logs",         AsyncMock(return_value=0)) as m_audit, \
         patch.object(tasks_module, "_cleanup_proxy_interactions", AsyncMock(return_value=0)) as m_proxy, \
         patch.object(tasks_module, "_cleanup_refresh_tokens",     AsyncMock(return_value=0)) as m_tokens:
        await run_retention_cleanup()

    m_audit.assert_awaited_once()
    m_proxy.assert_awaited_once()
    m_tokens.assert_awaited_once()
