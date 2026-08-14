# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
H1: webhook PEL recovery. A payload read but not acked before a worker dies must
not be lost. These exercise the two recovery paths against a REAL Redis stream:

  - read_own_pending: a restarted worker (stable consumer name) drains its own
    stranded entries (the shutdown-cancel loss path).
  - claim_stale (XAUTOCLAIM): another worker reclaims a DEAD replica's entries.
"""

import uuid

import pytest

from cache import webhook_queue
from cache.redis_client import get_redis


async def _clean(redis):
    for key in (webhook_queue.STREAM_MAIN, webhook_queue.STREAM_DLQ, webhook_queue.ZSET_DELAYED):
        await redis.delete(key)


@pytest.mark.asyncio
async def test_own_pending_recovers_stranded_entry():
    redis = get_redis()
    await _clean(redis)
    try:
        await webhook_queue.ensure_consumer_group(redis)
        mid = uuid.uuid4().hex
        await webhook_queue.enqueue(redis, {"msg_id": mid, "attempt_number": 1})

        # Consumer c1 reads the entry but never acks (crash/cancel before ack) ...
        got = await webhook_queue.read(redis, consumer="c1", count=10, block_ms=100)
        assert [p["msg_id"] for _sid, p in got] == [mid]

        # ... on restart, c1 drains its OWN pending entries (XREADGROUP id 0).
        recovered = await webhook_queue.read_own_pending(redis, "c1")
        assert [p["msg_id"] for _sid, p in recovered] == [mid]
    finally:
        await _clean(redis)


@pytest.mark.asyncio
async def test_claim_stale_recovers_dead_consumer_entry():
    redis = get_redis()
    await _clean(redis)
    try:
        await webhook_queue.ensure_consumer_group(redis)
        mid = uuid.uuid4().hex
        await webhook_queue.enqueue(redis, {"msg_id": mid, "attempt_number": 1})

        # A now-dead consumer read it and never acked ...
        got = await webhook_queue.read(redis, consumer="dead-replica", count=10, block_ms=100)
        assert len(got) == 1

        # ... a live worker reclaims idle entries (min_idle 0 -> immediately eligible).
        claimed = await webhook_queue.claim_stale(redis, consumer="live-replica", min_idle_ms=0)
        assert [p["msg_id"] for _sid, p in claimed] == [mid]

        # A high idle threshold would NOT reclaim a just-read (fresh) entry --
        # this is the guard against stealing a slow-but-alive worker's in-flight work.
        await webhook_queue.ack(redis, claimed[0][0])       # done with it
        mid2 = uuid.uuid4().hex
        await webhook_queue.enqueue(redis, {"msg_id": mid2, "attempt_number": 1})
        await webhook_queue.read(redis, consumer="dead-replica", count=10, block_ms=100)
        none_yet = await webhook_queue.claim_stale(redis, consumer="live-replica", min_idle_ms=600000)
        assert none_yet == []
    finally:
        await _clean(redis)
