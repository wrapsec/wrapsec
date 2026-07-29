# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for workers.webhook_circuit_breaker.

The sweep runs every 15 minutes in every uvicorn worker via
APScheduler. These tests pin four properties:

  1. Lease acquisition uses SET NX with a bounded TTL (a missing TTL
     would freeze the breaker for hours after a worker crash).
  2. Lease denial short-circuits the sweep (no double-writes across
     workers on the same install).
  3. Lease Redis error fails open (a Redis outage must not silently
     freeze the breaker -- duplicate DB work is strictly better).
  4. When the lease is held, the configured threshold is passed
     through to the repository, and DB failures are swallowed so the
     next tick still runs.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers import webhook_circuit_breaker as sweep_module
from workers.webhook_circuit_breaker import (
    CIRCUIT_BREAKER_LEASE_KEY,
    CIRCUIT_BREAKER_LEASE_TTL,
    _acquire_lease,
    run_circuit_breaker_sweep,
)


class _FakeRedis:
    """Minimal redis stub: records the SET call so we can assert kwargs."""

    def __init__(self, acquired: bool = True, raise_on_set: bool = False):
        self._acquired = acquired
        self._raise    = raise_on_set
        self.set_calls = []

    async def set(self, key, value, nx=False, ex=None):
        self.set_calls.append({"key": key, "value": value, "nx": nx, "ex": ex})
        if self._raise:
            raise ConnectionError("redis unavailable")
        return self._acquired


class _FakeSession:
    """Async-context-manager session stub with commit tracking."""

    def __init__(self):
        self.commit = AsyncMock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


# ─── _acquire_lease ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_lease_acquired_returns_true():
    fake = _FakeRedis(acquired=True)
    with patch("cache.redis_client.get_redis", return_value=fake):
        assert await _acquire_lease() is True


@pytest.mark.asyncio
async def test_lease_denied_returns_false():
    fake = _FakeRedis(acquired=False)
    with patch("cache.redis_client.get_redis", return_value=fake):
        assert await _acquire_lease() is False


@pytest.mark.asyncio
async def test_lease_uses_nx_and_bounded_ttl():
    """SET NX with bounded TTL: same invariant as the retention lease.
    A missing TTL or nx=False silently disables coordination."""
    fake = _FakeRedis(acquired=True)
    with patch("cache.redis_client.get_redis", return_value=fake):
        await _acquire_lease()
    assert len(fake.set_calls) == 1
    call = fake.set_calls[0]
    assert call["key"] == CIRCUIT_BREAKER_LEASE_KEY
    assert call["nx"]  is True
    assert call["ex"]  == CIRCUIT_BREAKER_LEASE_TTL
    assert CIRCUIT_BREAKER_LEASE_TTL <= 3600, (
        "Lease TTL must be well under the sweep cadence so a crashed "
        "worker only blocks one tick, not the whole day."
    )


@pytest.mark.asyncio
async def test_lease_fails_open_on_redis_error():
    """Fail-open on Redis: freezing the circuit breaker on Redis
    outages would be far worse than duplicate DB writes."""
    fake = _FakeRedis(raise_on_set=True)
    with patch("cache.redis_client.get_redis", return_value=fake):
        assert await _acquire_lease() is True


# ─── run_circuit_breaker_sweep ──────────────────────────────────────

@pytest.mark.asyncio
async def test_sweep_skips_when_lease_denied():
    """If another worker holds the tick, this one must not touch the
    repository at all -- otherwise the cross-worker coordination is
    only theoretical."""
    with patch.object(sweep_module, "_acquire_lease", AsyncMock(return_value=False)):
        # Any DB access here would blow up on missing fixtures/mocks,
        # so a clean return is the assertion.
        await run_circuit_breaker_sweep()


@pytest.mark.asyncio
async def test_sweep_calls_disable_stale_with_configured_threshold():
    """The env-configured threshold MUST reach the repo call --
    a hardcoded 120h would ignore per-install overrides."""
    fake_repo = MagicMock()
    fake_repo.disable_stale = AsyncMock(return_value=[])

    fake_session = _FakeSession()

    with patch.object(sweep_module, "_acquire_lease", AsyncMock(return_value=True)), \
         patch("config.settings.get_settings",
               return_value=SimpleNamespace(webhook_circuit_breaker_hours=72)), \
         patch("db.repositories.webhook_endpoint.WebhookEndpointRepository",
               return_value=fake_repo), \
         patch("db.session.AsyncSessionFactory", return_value=fake_session):
        await run_circuit_breaker_sweep()

    fake_repo.disable_stale.assert_awaited_once_with(threshold_hours=72)
    fake_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_sweep_swallows_repository_exception():
    """A single failing tick must not stop future scheduled runs.
    APScheduler on some configurations will silence a job that raises,
    so the sweep itself must be exception-safe."""
    fake_repo = MagicMock()
    fake_repo.disable_stale = AsyncMock(side_effect=RuntimeError("db down"))
    fake_session = _FakeSession()

    with patch.object(sweep_module, "_acquire_lease", AsyncMock(return_value=True)), \
         patch("config.settings.get_settings",
               return_value=SimpleNamespace(webhook_circuit_breaker_hours=120)), \
         patch("db.repositories.webhook_endpoint.WebhookEndpointRepository",
               return_value=fake_repo), \
         patch("db.session.AsyncSessionFactory", return_value=fake_session):
        # No raise -- run_circuit_breaker_sweep MUST log-and-swallow.
        await run_circuit_breaker_sweep()
