# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for workers.webhook_delivery -- the loop that drains the outbound
webhook queue and reconciles handler outcomes with the queue transitions.

Redis is fully mocked. `cache.webhook_queue` is patched at the module
boundary so we can assert *which* transition (ack | requeue | dlq) fired for
each outcome without pulling in a live Redis. The handler itself is a small
async stub; real HTTP delivery lands in a later v1.3.0 commit.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from workers import webhook_delivery
from workers.webhook_delivery import (
    DeliveryOutcome,
    DeliveryResult,
    default_consumer_name,
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


# ─── default_consumer_name ───────────────────────────────────────────────

def test_default_consumer_name_shape():
    """hostname:pid so XCLAIM can reassign a dead worker's PEL entries."""
    name = default_consumer_name()
    assert ":" in name
    host, pid = name.rsplit(":", 1)
    assert host
    assert pid.isdigit()


# ─── _dispatch_one: success / retry / dlq ────────────────────────────────

@pytest.mark.asyncio
async def test_dispatch_success_acks_only():
    redis = AsyncMock()
    handler = AsyncMock(return_value=DeliveryOutcome(result=DeliveryResult.SUCCESS))

    with patch.object(webhook_delivery.webhook_queue, "ack", new=AsyncMock()) as ack, \
         patch.object(webhook_delivery.webhook_queue, "enqueue_delayed", new=AsyncMock()) as delayed, \
         patch.object(webhook_delivery.webhook_queue, "move_to_dlq", new=AsyncMock()) as dlq:

        sem = asyncio.Semaphore(1)
        await webhook_delivery._dispatch_one(redis, handler, "1-0", _payload(), sem)

        ack.assert_awaited_once_with(redis, "1-0")
        delayed.assert_not_called()
        dlq.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_retry_requeues_and_acks():
    redis = AsyncMock()
    handler = AsyncMock(
        return_value=DeliveryOutcome(result=DeliveryResult.RETRY, retry_in_s=300)
    )

    with patch.object(webhook_delivery.webhook_queue, "ack", new=AsyncMock()) as ack, \
         patch.object(webhook_delivery.webhook_queue, "enqueue_delayed", new=AsyncMock()) as delayed, \
         patch.object(webhook_delivery.webhook_queue, "move_to_dlq", new=AsyncMock()) as dlq, \
         patch.object(webhook_delivery, "_now_ts", return_value=1_000):

        sem = asyncio.Semaphore(1)
        await webhook_delivery._dispatch_one(redis, handler, "1-0", _payload(), sem)

        delayed.assert_awaited_once()
        _, _kwargs = delayed.call_args
        args = delayed.call_args.args
        # (redis, payload, run_at_ts) -- run_at should be now + retry_in_s.
        assert args[2] == 1_300
        # Ack removes the entry from the current PEL so the requeued copy is
        # the only live one.
        ack.assert_awaited_once_with(redis, "1-0")
        dlq.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_retry_bumps_attempt_number():
    """The requeued payload must advance attempt_number so the retry schedule
    progresses and eventually exhausts into the DLQ instead of retrying at the
    first (5s) slot forever."""
    redis = AsyncMock()
    handler = AsyncMock(
        return_value=DeliveryOutcome(result=DeliveryResult.RETRY, retry_in_s=300)
    )
    payload = _payload(attempt_number=2)

    with patch.object(webhook_delivery.webhook_queue, "ack", new=AsyncMock()), \
         patch.object(webhook_delivery.webhook_queue, "enqueue_delayed", new=AsyncMock()) as delayed, \
         patch.object(webhook_delivery.webhook_queue, "move_to_dlq", new=AsyncMock()), \
         patch.object(webhook_delivery, "_now_ts", return_value=1_000):

        sem = asyncio.Semaphore(1)
        await webhook_delivery._dispatch_one(redis, handler, "1-0", payload, sem)

        requeued = delayed.call_args.args[1]
        assert requeued["attempt_number"] == 3
        # The original payload is not mutated in place.
        assert payload["attempt_number"] == 2


@pytest.mark.asyncio
async def test_dispatch_dlq_moves_and_does_not_requeue():
    redis = AsyncMock()
    handler = AsyncMock(
        return_value=DeliveryOutcome(result=DeliveryResult.DLQ, dlq_reason="endpoint_disabled")
    )

    with patch.object(webhook_delivery.webhook_queue, "ack", new=AsyncMock()) as ack, \
         patch.object(webhook_delivery.webhook_queue, "enqueue_delayed", new=AsyncMock()) as delayed, \
         patch.object(webhook_delivery.webhook_queue, "move_to_dlq", new=AsyncMock()) as dlq:

        sem = asyncio.Semaphore(1)
        await webhook_delivery._dispatch_one(redis, handler, "1-0", _payload(), sem)

        dlq.assert_awaited_once_with(redis, "1-0", _payload(), "endpoint_disabled")
        # move_to_dlq internally acks; the loop must not double-ack.
        ack.assert_not_called()
        delayed.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_handler_exception_falls_back_to_retry():
    """A raising handler must not drop the entry -- worker requeues with a
    short default backoff."""
    redis = AsyncMock()
    handler = AsyncMock(side_effect=RuntimeError("boom"))

    with patch.object(webhook_delivery.webhook_queue, "ack", new=AsyncMock()) as ack, \
         patch.object(webhook_delivery.webhook_queue, "enqueue_delayed", new=AsyncMock()) as delayed, \
         patch.object(webhook_delivery.webhook_queue, "move_to_dlq", new=AsyncMock()) as dlq, \
         patch.object(webhook_delivery, "_now_ts", return_value=2_000):

        sem = asyncio.Semaphore(1)
        await webhook_delivery._dispatch_one(redis, handler, "1-0", _payload(), sem)

        delayed.assert_awaited_once()
        assert delayed.call_args.args[2] == 2_000 + 60  # fallback backoff
        ack.assert_awaited_once_with(redis, "1-0")
        dlq.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_retry_without_retry_in_s_uses_default_backoff():
    """A RETRY outcome with no retry_in_s is a handler bug; entry must still
    survive with a sane default rather than being dropped."""
    redis = AsyncMock()
    handler = AsyncMock(return_value=DeliveryOutcome(result=DeliveryResult.RETRY))

    with patch.object(webhook_delivery.webhook_queue, "ack", new=AsyncMock()), \
         patch.object(webhook_delivery.webhook_queue, "enqueue_delayed", new=AsyncMock()) as delayed, \
         patch.object(webhook_delivery.webhook_queue, "move_to_dlq", new=AsyncMock()), \
         patch.object(webhook_delivery, "_now_ts", return_value=5_000):

        sem = asyncio.Semaphore(1)
        await webhook_delivery._dispatch_one(redis, handler, "1-0", _payload(), sem)

        delayed.assert_awaited_once()
        assert delayed.call_args.args[2] == 5_060


# ─── run: loop lifecycle ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_stops_on_event_and_drains_in_flight():
    """
    Wire up the full loop with fake queue functions:
      - promote_delayed is a no-op
      - read returns one batch then blocks (returns [] on subsequent calls)
      - handler returns SUCCESS
      - stop_event is set after the first read
    The loop should exit cleanly and have acked the batch entry.
    """
    redis = AsyncMock()
    stop_event = asyncio.Event()

    read_calls = {"n": 0}

    async def fake_read(redis, consumer, count, block_ms):
        read_calls["n"] += 1
        if read_calls["n"] == 1:
            return [("1-0", _payload())]
        stop_event.set()
        return []

    with patch.object(webhook_delivery.webhook_queue, "ensure_consumer_group", new=AsyncMock()) as ensure, \
         patch.object(webhook_delivery.webhook_queue, "promote_delayed",       new=AsyncMock(return_value=0)), \
         patch.object(webhook_delivery.webhook_queue, "read",                  new=fake_read), \
         patch.object(webhook_delivery.webhook_queue, "ack",                   new=AsyncMock()) as ack, \
         patch.object(webhook_delivery.webhook_queue, "enqueue_delayed",       new=AsyncMock()), \
         patch.object(webhook_delivery.webhook_queue, "move_to_dlq",           new=AsyncMock()):

        handler = AsyncMock(return_value=DeliveryOutcome(result=DeliveryResult.SUCCESS))

        await asyncio.wait_for(
            webhook_delivery.run(
                redis         = redis,
                handler       = handler,
                consumer      = "test:1",
                stop_event    = stop_event,
                concurrency   = 4,
                batch         = 10,
                poll_block_ms = 10,
            ),
            timeout=2.0,
        )

        ensure.assert_awaited_once()
        handler.assert_awaited_once()
        ack.assert_awaited_once_with(redis, "1-0")


@pytest.mark.asyncio
async def test_run_backs_off_on_read_exception():
    """XREADGROUP failure logs and sleeps; does not crash the loop."""
    redis = AsyncMock()
    stop_event = asyncio.Event()

    read_calls = {"n": 0}

    async def fake_read(redis, consumer, count, block_ms):
        read_calls["n"] += 1
        if read_calls["n"] == 1:
            raise RuntimeError("redis blew up")
        stop_event.set()
        return []

    async def fast_sleep(_):
        # Compress the 1s back-off so the test stays quick.
        return None

    with patch.object(webhook_delivery.webhook_queue, "ensure_consumer_group", new=AsyncMock()), \
         patch.object(webhook_delivery.webhook_queue, "promote_delayed",       new=AsyncMock(return_value=0)), \
         patch.object(webhook_delivery.webhook_queue, "read",                  new=fake_read), \
         patch.object(webhook_delivery.asyncio, "sleep",                       new=fast_sleep):

        handler = AsyncMock()

        await asyncio.wait_for(
            webhook_delivery.run(
                redis      = redis,
                handler    = handler,
                consumer   = "test:1",
                stop_event = stop_event,
            ),
            timeout=2.0,
        )

        assert read_calls["n"] >= 2  # first raised, second returned []
        handler.assert_not_called()
