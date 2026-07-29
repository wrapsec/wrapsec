# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for cache.webhook_queue -- the Redis Streams primitives that back
outbound webhook delivery.

Redis is mocked with AsyncMock so these tests run without a live Redis
instance. Integration coverage against a real Redis lands with the delivery
worker end-to-end tests in a later v1.3.0 commit.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from redis.exceptions import ResponseError

from cache import webhook_queue
from cache.webhook_queue import (
    CONSUMER_GROUP,
    STREAM_DLQ,
    STREAM_MAIN,
    ZSET_DELAYED,
)


def _payload(**overrides):
    base = {
        "endpoint_id":    "ep-1",
        "tenant_id":      "t-1",
        "msg_id":         "m-1",
        "event_type":     "wrapsec.request.blocked",
        "attempt_number": 1,
        "body":           '{"hello":"world"}',
    }
    base.update(overrides)
    return base


# ─── ensure_consumer_group ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ensure_consumer_group_creates_with_mkstream():
    redis = AsyncMock()
    await webhook_queue.ensure_consumer_group(redis)
    redis.xgroup_create.assert_awaited_once_with(
        name      = STREAM_MAIN,
        groupname = CONSUMER_GROUP,
        id        = "0",
        mkstream  = True,
    )


@pytest.mark.asyncio
async def test_ensure_consumer_group_swallows_busygroup():
    redis = AsyncMock()
    redis.xgroup_create.side_effect = ResponseError("BUSYGROUP Consumer Group name already exists")
    # Should not raise.
    await webhook_queue.ensure_consumer_group(redis)


@pytest.mark.asyncio
async def test_ensure_consumer_group_reraises_other_errors():
    redis = AsyncMock()
    redis.xgroup_create.side_effect = ResponseError("some other redis error")
    with pytest.raises(ResponseError):
        await webhook_queue.ensure_consumer_group(redis)


# ─── enqueue ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enqueue_xadds_json_payload_and_returns_stream_id():
    redis = AsyncMock()
    redis.xadd.return_value = "1753500000000-0"

    stream_id = await webhook_queue.enqueue(redis, _payload())

    assert stream_id == "1753500000000-0"
    args, kwargs = redis.xadd.call_args
    assert args[0] == STREAM_MAIN
    # payload field is a single JSON blob, round-trippable.
    assert set(args[1].keys()) == {"p"}
    assert json.loads(args[1]["p"])["msg_id"] == "m-1"


# ─── enqueue_delayed ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enqueue_delayed_zadds_with_run_at_score():
    redis = AsyncMock()
    await webhook_queue.enqueue_delayed(redis, _payload(), run_at_ts=1_753_500_600)

    redis.zadd.assert_awaited_once()
    args, _ = redis.zadd.call_args
    assert args[0] == ZSET_DELAYED
    mapping = args[1]
    assert len(mapping) == 1
    (member, score), = mapping.items()
    assert score == 1_753_500_600
    assert json.loads(member)["msg_id"] == "m-1"


# ─── promote_delayed ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_promote_delayed_returns_zero_when_nothing_due():
    redis = AsyncMock()
    redis.zrangebyscore.return_value = []

    moved = await webhook_queue.promote_delayed(redis, now_ts=1_000)

    assert moved == 0
    redis.pipeline.assert_not_called()


@pytest.mark.asyncio
async def test_promote_delayed_moves_due_entries_via_pipeline():
    redis = AsyncMock()

    due_members = [json.dumps(_payload(msg_id=f"m-{i}")) for i in range(3)]
    redis.zrangebyscore.return_value = due_members

    # AsyncMock pipeline context manager -- record the operations queued.
    pipe = MagicMock()
    pipe.xadd = MagicMock()
    pipe.zrem = MagicMock()
    pipe.execute = AsyncMock(return_value=[None] * 6)
    pipe_cm = MagicMock()
    pipe_cm.__aenter__ = AsyncMock(return_value=pipe)
    pipe_cm.__aexit__  = AsyncMock(return_value=False)
    redis.pipeline = MagicMock(return_value=pipe_cm)

    moved = await webhook_queue.promote_delayed(redis, now_ts=1_000)

    assert moved == 3
    # Each due entry should have generated one XADD + one ZREM inside the pipe.
    assert pipe.xadd.call_count == 3
    assert pipe.zrem.call_count == 3
    pipe.execute.assert_awaited_once()


# ─── read ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_read_returns_empty_list_on_no_response():
    redis = AsyncMock()
    redis.xreadgroup.return_value = None

    out = await webhook_queue.read(redis, consumer="host:1")

    assert out == []


@pytest.mark.asyncio
async def test_read_decodes_payloads_and_returns_stream_id_pairs():
    redis = AsyncMock()
    p1 = _payload(msg_id="m-1")
    p2 = _payload(msg_id="m-2")
    redis.xreadgroup.return_value = [
        (STREAM_MAIN, [
            ("1-0", {"p": json.dumps(p1)}),
            ("2-0", {"p": json.dumps(p2)}),
        ]),
    ]

    out = await webhook_queue.read(redis, consumer="host:1")

    assert [sid for sid, _ in out] == ["1-0", "2-0"]
    assert [pl["msg_id"] for _, pl in out] == ["m-1", "m-2"]


@pytest.mark.asyncio
async def test_read_acks_and_skips_malformed_json_entries():
    redis = AsyncMock()
    redis.xreadgroup.return_value = [
        (STREAM_MAIN, [
            ("1-0", {"p": "not json"}),
        ]),
    ]

    out = await webhook_queue.read(redis, consumer="host:1")

    assert out == []
    # Malformed entry got acked so it does not loop forever in the PEL.
    redis.xack.assert_awaited_once_with(STREAM_MAIN, CONSUMER_GROUP, "1-0")


@pytest.mark.asyncio
async def test_read_skips_entries_with_missing_payload_field():
    redis = AsyncMock()
    redis.xreadgroup.return_value = [
        (STREAM_MAIN, [
            ("1-0", {"unrelated": "x"}),
        ]),
    ]

    out = await webhook_queue.read(redis, consumer="host:1")
    assert out == []
    # No payload field means we do NOT ack -- this is a producer bug and
    # should stay visible for triage rather than being silently dropped.
    redis.xack.assert_not_called()


# ─── ack / move_to_dlq ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ack_calls_xack_on_main_stream():
    redis = AsyncMock()
    await webhook_queue.ack(redis, "42-0")
    redis.xack.assert_awaited_once_with(STREAM_MAIN, CONSUMER_GROUP, "42-0")


@pytest.mark.asyncio
async def test_move_to_dlq_pushes_annotated_payload_and_acks_main():
    redis = AsyncMock()
    payload = _payload()

    await webhook_queue.move_to_dlq(redis, "42-0", payload, reason="retry_exhausted")

    # DLQ XADD carries the original payload plus a reason field.
    dlq_call = redis.xadd.await_args_list[0]
    assert dlq_call.args[0] == STREAM_DLQ
    body = json.loads(dlq_call.args[1]["p"])
    assert body["_dlq_reason"] == "retry_exhausted"
    assert body["msg_id"] == payload["msg_id"]
    # And the main stream entry got acked to keep the PEL clean.
    redis.xack.assert_awaited_once_with(STREAM_MAIN, CONSUMER_GROUP, "42-0")
