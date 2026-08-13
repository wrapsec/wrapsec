# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Redis Streams queue primitives for outbound webhook delivery (v1.3.0).

Three Redis keys back the delivery pipeline:

    wrapsec:webhooks:main      XSTREAM  - ready-to-deliver messages
    wrapsec:webhooks:delayed   ZSET     - scheduled retries (score = unix seconds)
    wrapsec:webhooks:dlq       XSTREAM  - permanently failed messages

A single consumer group `webhook_workers` reads from the main stream.
Every worker process joins with a unique consumer name (hostname:pid)
so Redis can reassign pending messages when a worker dies -- the PEL
(pending entries list) tracks which consumer holds which unacked entry.

The delayed sorted set is a scheduled-retry buffer. When a delivery
fails and the retry schedule says "try again in 5 minutes", the
payload is ZADD-ed to `delayed` with score = unix_seconds(now + 5m).
`promote_delayed` moves items whose score <= now() from the delayed
set into the main stream, at which point they become visible to the
next XREADGROUP call. That promote step is intentionally coarse-
grained (a batch pass) rather than per-message so it can be cheap
to run on a short interval from the worker loop.

The DLQ stream captures messages that have exhausted their retry
schedule or hit a permanent error (endpoint disabled, malformed
payload, etc.). Moving to DLQ also XACKs the message off the main
stream so the consumer-group PEL does not grow unbounded.

Payload wire format (JSON dict):

    {
      "endpoint_id":    "<uuid>",
      "tenant_id":      "<uuid>",
      "msg_id":         "<stable-message-id>",
      "event_type":     "wrapsec.request.blocked",
      "attempt_number": 1,
      "body":           "<serialized event body>",
    }

This module is a pure queue-primitive layer. It knows about Redis and
the wire format only; signing, HTTP, retry-schedule computation, and
circuit-breaker decisions all live in the delivery worker (later
v1.3.0 commits).
"""

from __future__ import annotations

import json
import time
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import ResponseError

# Redis keys. Constants (not settings) because rename would be a
# migration event; every deployment must agree.
STREAM_MAIN    = "wrapsec:webhooks:main"
STREAM_DLQ     = "wrapsec:webhooks:dlq"
ZSET_DELAYED   = "wrapsec:webhooks:delayed"
CONSUMER_GROUP = "webhook_workers"

# Payload is stored under a single field so XADD/XREADGROUP round-trip
# the whole JSON blob as one string. Field-per-key would spread the
# blob across a hash and force multiple encoders on the worker side.
_PAYLOAD_FIELD = "p"


async def ensure_consumer_group(redis: Redis) -> None:
    """
    Create the consumer group if it does not already exist.

    Uses MKSTREAM so the group can be created before the first XADD.
    Idempotent -- the BUSYGROUP error from a re-create is swallowed.
    Call once at worker startup.
    """
    try:
        await redis.xgroup_create(
            name        = STREAM_MAIN,
            groupname   = CONSUMER_GROUP,
            id          = "0",
            mkstream    = True,
        )
    except ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


async def enqueue(redis: Redis, payload: dict[str, Any]) -> str:
    """
    XADD a payload onto the main stream. Returns the assigned stream id.

    The stream id (e.g. "1753500000000-0") is redis-assigned and used
    later for XACK; it is NOT the caller's msg_id (which appears inside
    the payload).
    """
    return await redis.xadd(STREAM_MAIN, {_PAYLOAD_FIELD: json.dumps(payload)})


async def enqueue_delayed(
    redis:      Redis,
    payload:    dict[str, Any],
    run_at_ts:  int,
) -> None:
    """
    ZADD a payload onto the delayed sorted set with `run_at_ts` as score.

    The payload is JSON-encoded as the ZSET member; identical payloads
    scheduled twice would collapse into one entry (which is intended --
    duplicate retries are wasteful, and the attempt_number field
    distinguishes real re-schedules from replays).
    """
    await redis.zadd(ZSET_DELAYED, {json.dumps(payload): run_at_ts})


async def promote_delayed(
    redis:  Redis,
    now_ts: int | None = None,
    batch:  int = 100,
) -> int:
    """
    Move all delayed entries with score <= now_ts onto the main stream.

    Returns the number of items promoted. Called on a short interval
    from the worker loop; if nothing is due, this is one cheap ZRANGE.
    """
    if now_ts is None:
        now_ts = int(time.time())

    due = await redis.zrangebyscore(
        ZSET_DELAYED,
        min   = "-inf",
        max   = now_ts,
        start = 0,
        num   = batch,
    )
    if not due:
        return 0

    # Pipeline the promote so all items move atomically per batch.
    async with redis.pipeline(transaction=True) as pipe:
        for member in due:
            pipe.xadd(STREAM_MAIN, {_PAYLOAD_FIELD: member})
            pipe.zrem(ZSET_DELAYED, member)
        await pipe.execute()

    return len(due)


async def read(
    redis:    Redis,
    consumer: str,
    count:    int  = 10,
    block_ms: int  = 5000,
) -> list[tuple[str, dict[str, Any]]]:
    """
    XREADGROUP a batch of ready messages for this consumer.

    Returns a list of (stream_id, payload) tuples. Empty list on timeout
    or when the stream is idle. Callers must XACK each stream_id they
    finish processing (via `ack`) or the message stays in the PEL and
    will be re-delivered by XCLAIM after visibility timeout.
    """
    resp = await redis.xreadgroup(
        groupname = CONSUMER_GROUP,
        consumername = consumer,
        streams   = {STREAM_MAIN: ">"},
        count     = count,
        block     = block_ms,
    )
    if not resp:
        return []

    out: list[tuple[str, dict[str, Any]]] = []
    for _stream, entries in resp:
        for stream_id, fields in entries:
            raw = fields.get(_PAYLOAD_FIELD)
            if raw is None:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                # Malformed entry -- ack it out so it does not loop forever;
                # a DLQ push is not useful because the payload itself is broken.
                await redis.xack(STREAM_MAIN, CONSUMER_GROUP, stream_id)
                continue
            out.append((stream_id, payload))
    return out


async def ack(redis: Redis, stream_id: str) -> None:
    """XACK a successfully-processed entry off the main stream's PEL."""
    await redis.xack(STREAM_MAIN, CONSUMER_GROUP, stream_id)


async def move_to_dlq(
    redis:      Redis,
    stream_id:  str,
    payload:    dict[str, Any],
    reason:     str,
) -> None:
    """
    Push a permanently-failed message to the DLQ stream and XACK it off
    the main stream so the PEL does not accumulate dead entries.

    `reason` is a short human-readable string (e.g.
    "retry_exhausted", "endpoint_disabled", "invalid_payload") that
    operators can filter on when triaging the DLQ.
    """
    dlq_payload = {**payload, "_dlq_reason": reason}
    await redis.xadd(STREAM_DLQ, {_PAYLOAD_FIELD: json.dumps(dlq_payload)})
    await redis.xack(STREAM_MAIN, CONSUMER_GROUP, stream_id)
