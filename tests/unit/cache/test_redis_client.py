# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for cache.redis_client.

Covers the dedicated webhook-worker client, whose whole reason to exist is
that its socket timeout must exceed the delivery worker's blocking stream
read -- otherwise the read aborts every idle cycle on the shared 2s pool.
"""

from __future__ import annotations

import inspect

import pytest

from cache import redis_client
from workers.webhook_delivery import run as worker_run


@pytest.mark.asyncio
async def test_worker_redis_socket_timeout_exceeds_blocking_read():
    block_ms = inspect.signature(worker_run).parameters["poll_block_ms"].default

    client = redis_client.get_webhook_worker_redis()
    try:
        kwargs = client.connection_pool.connection_kwargs
        assert kwargs["decode_responses"] is True
        # The invariant: socket timeout (seconds) must sit above the blocking
        # XREADGROUP window (ms) or the read trips the timeout while idle.
        assert kwargs["socket_timeout"] * 1000 > block_ms
    finally:
        await redis_client.close_webhook_worker_redis()


@pytest.mark.asyncio
async def test_worker_redis_is_a_distinct_singleton():
    a = redis_client.get_webhook_worker_redis()
    b = redis_client.get_webhook_worker_redis()
    try:
        assert a is b                                   # memoized
        assert a is not redis_client.get_redis()        # not the shared hot-path client
    finally:
        await redis_client.close_webhook_worker_redis()
