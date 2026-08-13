# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_pipeline_mock(count_result: int):
    """
    Return (redis_mock, pipe_mock) with a correctly wired async context manager.
    redis.pipeline() must be a regular callable returning a CM, not an async method.
    pipe.incr/expire are sync (they queue commands); pipe.execute is async.
    """
    mock_pipe = MagicMock()
    mock_pipe.incr    = MagicMock()
    mock_pipe.expire  = MagicMock()
    mock_pipe.execute = AsyncMock(return_value=[count_result, True])

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_pipe)
    cm.__aexit__  = AsyncMock(return_value=False)

    mock_redis = MagicMock()
    mock_redis.pipeline = MagicMock(return_value=cm)
    mock_redis.setex    = AsyncMock()
    mock_redis.exists   = AsyncMock(return_value=0)
    mock_redis.delete   = AsyncMock()
    mock_redis.ttl      = AsyncMock(return_value=-1)
    return mock_redis, mock_pipe


# ── Key naming ─────────────────────────────────────────────────────────────────

def test_failed_key_format():
    from services.auth.lockout import _failed_key
    assert _failed_key("user@example.com") == "auth:failed:user@example.com"


def test_locked_key_format():
    from services.auth.lockout import _locked_key
    assert _locked_key("user@example.com") == "auth:locked:user@example.com"


def test_keys_are_email_scoped():
    from services.auth.lockout import _failed_key, _locked_key
    # Different emails produce different keys
    assert _failed_key("a@example.com") != _failed_key("b@example.com")
    assert _locked_key("a@example.com") != _locked_key("b@example.com")


# ── is_locked ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_not_locked_when_key_absent():
    mock_redis = AsyncMock()
    mock_redis.exists = AsyncMock(return_value=0)
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import is_locked
        result = await is_locked("user@example.com")
    assert result is False


@pytest.mark.asyncio
async def test_locked_when_key_present():
    mock_redis = AsyncMock()
    mock_redis.exists = AsyncMock(return_value=1)
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import is_locked
        result = await is_locked("user@example.com")
    assert result is True


# ── record_failure ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_record_increments_counter():
    mock_redis, mock_pipe = _make_pipeline_mock(count_result=1)
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import record_failure
        count, locked = await record_failure("user@example.com")
    assert count == 1
    assert locked is False
    mock_pipe.incr.assert_called_once()


@pytest.mark.asyncio
async def test_failure_sets_ttl_via_pipeline():
    """expire is always called in the pipeline (sliding window - intentional)."""
    mock_redis, mock_pipe = _make_pipeline_mock(count_result=1)
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import record_failure
        await record_failure("user@example.com")
    mock_pipe.expire.assert_called_once()


@pytest.mark.asyncio
async def test_subsequent_failure_also_resets_ttl():
    """Sliding window - expire is called on every failure, not just the first."""
    mock_redis, mock_pipe = _make_pipeline_mock(count_result=2)
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import record_failure
        await record_failure("user@example.com")
    mock_pipe.expire.assert_called_once()


@pytest.mark.asyncio
async def test_at_max_attempts_sets_lock():
    mock_redis, _ = _make_pipeline_mock(count_result=5)  # equals max
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import record_failure
        _count, locked = await record_failure("user@example.com")
    assert locked is True
    mock_redis.setex.assert_called_once()


@pytest.mark.asyncio
async def test_beyond_max_extends_lock_ttl():
    """Attacker who keeps retrying extends their own lockout via setex overwrite."""
    mock_redis, _ = _make_pipeline_mock(count_result=10)  # beyond max
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import record_failure
        _count, locked = await record_failure("user@example.com")
    assert locked is True
    mock_redis.setex.assert_called_once()


# ── clear_failures ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clear_removes_both_keys():
    mock_redis = AsyncMock()
    mock_redis.delete = AsyncMock()
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import clear_failures
        await clear_failures("user@example.com")
    assert mock_redis.delete.call_count == 2


# ── get_lockout_remaining ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_remaining_positive_when_locked():
    mock_redis = AsyncMock()
    mock_redis.ttl = AsyncMock(return_value=847)
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import get_lockout_remaining
        result = await get_lockout_remaining("user@example.com")
    assert result == 847


@pytest.mark.asyncio
async def test_remaining_zero_when_not_locked():
    mock_redis = AsyncMock()
    mock_redis.ttl = AsyncMock(return_value=-1)  # key does not exist
    with patch("services.auth.lockout.get_redis", return_value=mock_redis):
        from services.auth.lockout import get_lockout_remaining
        result = await get_lockout_remaining("user@example.com")
    assert result == 0
