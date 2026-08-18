# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging

from redis.asyncio import ConnectionPool, Redis

from config.settings import get_settings

logger = logging.getLogger("wrapsec.cache")

_pool: ConnectionPool | None = None
_client: Redis | None = None


def get_redis_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool.from_url(
            get_settings().redis_url,
            max_connections   = 20,
            decode_responses  = True,
            socket_timeout    = 2,        # fail fast on ping
            socket_connect_timeout = 2,
        )
    return _pool


def get_redis() -> Redis:
    global _client
    if _client is None:
        _client = Redis(connection_pool=get_redis_pool())
    return _client


async def ping() -> bool:
    """Always creates a fresh connection for health checks - never uses cached pool."""
    try:
        fresh = Redis.from_url(
            get_settings().redis_url,
            socket_timeout         = 2,
            socket_connect_timeout = 2,
            decode_responses       = True,
        )
        result = await fresh.ping()  # type: ignore  # async client method carries a sync-typed return stub
        await fresh.aclose()
        return result
    except Exception as e:
        logger.error(f"Redis ping failed: {e}")
        return False


async def close() -> None:
    global _client, _pool
    if _client:
        await _client.aclose()
        _client = None
    if _pool:
        await _pool.aclose()
        _pool = None


# Dedicated client for the outbound webhook delivery worker. The shared pool
# above uses socket_timeout=2s (fail-fast for the request hot path), but the
# worker does a ~5s blocking XREADGROUP; on the shared client that read would
# abort at 2s every idle cycle (spin + log noise) and tie up a hot-path
# connection. This client's socket timeout sits comfortably above the block.
_worker_client: Redis | None = None

# Must exceed the worker's poll_block_ms (5s) so the blocking read completes
# normally instead of tripping the socket timeout.
_WORKER_SOCKET_TIMEOUT = 30


def get_webhook_worker_redis() -> Redis:
    global _worker_client
    if _worker_client is None:
        _worker_client = Redis.from_url(
            get_settings().redis_url,
            decode_responses       = True,
            socket_timeout         = _WORKER_SOCKET_TIMEOUT,
            socket_connect_timeout = 5,
        )
    return _worker_client


async def close_webhook_worker_redis() -> None:
    global _worker_client
    if _worker_client:
        await _worker_client.aclose()
        _worker_client = None