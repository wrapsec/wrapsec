# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Outbound webhook delivery worker (v1.3.0).

Reads payloads off the Redis Streams queue defined in cache.webhook_queue,
hands each one to a caller-supplied `handler` coroutine, and reconciles the
handler's outcome with the queue: success acks off the PEL, retry re-schedules
the payload into the delayed sorted set (and acks it off the current PEL so
the entry does not appear twice), and dlq pushes to the dead-letter stream
(also acking off main).

This module is intentionally handler-agnostic. The concrete HTTP client,
signing, per-endpoint secret load, and retry-schedule computation all live in
downstream commits and are injected as `handler`; that keeps the queue loop
easy to unit-test without any network stack.

Loop shape per iteration:

    1. promote_delayed   -- move due retries from ZSET into main stream
    2. XREADGROUP        -- pull a batch (default 10) with a block timeout
    3. dispatch          -- run handler(payload) under Semaphore(concurrency)
    4. reconcile outcome -- ack | requeue+ack | dlq

Concurrency is capped by a Semaphore so a single worker cannot open unbounded
in-flight HTTP requests against slow endpoints. The stop_event pattern lets
the FastAPI lifespan gracefully cancel the loop on shutdown; in-flight
handlers finish under a bounded await before the loop exits.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable

from redis.asyncio import Redis

from cache import webhook_queue

logger = logging.getLogger("wrapsec.webhook_worker")


class DeliveryResult(str, Enum):
    """
    Outcome of a single handler invocation. The worker uses this to decide
    which queue transition to apply.
    """
    SUCCESS = "success"   # ack off main stream, done
    RETRY   = "retry"     # zadd back to delayed set, ack off main
    DLQ     = "dlq"       # xadd to dlq stream, ack off main


@dataclass
class DeliveryOutcome:
    """
    Return value from a delivery handler.

    `retry_in_s` is required when result is RETRY (unix-seconds offset from
    now at which the payload becomes eligible again). `dlq_reason` is a short
    label that surfaces in the DLQ payload for operator triage.
    """
    result:     DeliveryResult
    retry_in_s: int | None = None
    dlq_reason: str | None = None


DeliveryHandler = Callable[[dict], Awaitable[DeliveryOutcome]]


def default_consumer_name() -> str:
    """
    Consumer name uniquely identifying this worker process in the Redis
    consumer group. `hostname:pid` is stable per-process and distinct across
    replicas, which is what XCLAIM needs to reassign a dead worker's pending
    entries.
    """
    return f"{socket.gethostname()}:{os.getpid()}"


async def _dispatch_one(
    redis:      Redis,
    handler:    DeliveryHandler,
    stream_id:  str,
    payload:    dict,
    sem:        asyncio.Semaphore,
) -> None:
    """
    Run one handler invocation under the concurrency semaphore and apply the
    outcome to the queue. Any exception the handler raises is treated as a
    transient failure and returned to the delayed set with a short backoff;
    the retry-schedule module owned by the handler is the source of truth for
    real backoff, this fallback exists so a buggy handler cannot silently
    drop entries.
    """
    async with sem:
        try:
            outcome = await handler(payload)
        except Exception as exc:                          # noqa: BLE001
            logger.exception(
                "webhook handler raised, requeueing with 60s backoff: %s", exc
            )
            outcome = DeliveryOutcome(result=DeliveryResult.RETRY, retry_in_s=60)

        if outcome.result is DeliveryResult.SUCCESS:
            await webhook_queue.ack(redis, stream_id)
            return

        if outcome.result is DeliveryResult.RETRY:
            # A missing retry_in_s indicates a handler bug; fall back to a
            # small default so we never lose the entry.
            delay = outcome.retry_in_s if outcome.retry_in_s is not None else 60
            run_at = _now_ts() + max(1, delay)
            await webhook_queue.enqueue_delayed(redis, payload, run_at)
            await webhook_queue.ack(redis, stream_id)
            return

        if outcome.result is DeliveryResult.DLQ:
            reason = outcome.dlq_reason or "unspecified"
            await webhook_queue.move_to_dlq(redis, stream_id, payload, reason)
            return


def _now_ts() -> int:
    # Wrapped so tests can monkeypatch a fixed clock.
    import time
    return int(time.time())


async def run(
    redis:            Redis,
    handler:          DeliveryHandler,
    consumer:         str | None = None,
    stop_event:       asyncio.Event | None = None,
    concurrency:      int = 8,
    batch:            int = 10,
    poll_block_ms:    int = 5000,
) -> None:
    """
    Worker main loop. Runs until `stop_event` is set (or forever if None).

    Call from a supervisor coroutine (e.g. FastAPI lifespan) with an
    asyncio.Event you can .set() on shutdown. The loop returns cleanly after
    the current batch drains -- in-flight handlers are awaited via the
    semaphore before return so no delivery is orphaned mid-flight.
    """
    if consumer is None:
        consumer = default_consumer_name()
    if stop_event is None:
        stop_event = asyncio.Event()

    await webhook_queue.ensure_consumer_group(redis)

    sem     = asyncio.Semaphore(concurrency)
    in_flight: set[asyncio.Task] = set()

    logger.info("webhook worker started: consumer=%s concurrency=%d", consumer, concurrency)

    try:
        while not stop_event.is_set():
            # Move any due retries into the main stream first so the same
            # XREADGROUP call can pick them up alongside fresh entries.
            try:
                await webhook_queue.promote_delayed(redis)
            except Exception as exc:                      # noqa: BLE001
                logger.exception("promote_delayed failed: %s", exc)

            try:
                entries = await webhook_queue.read(
                    redis,
                    consumer  = consumer,
                    count     = batch,
                    block_ms  = poll_block_ms,
                )
            except Exception as exc:                      # noqa: BLE001
                logger.exception("XREADGROUP failed, backing off 1s: %s", exc)
                await asyncio.sleep(1.0)
                continue

            for stream_id, payload in entries:
                task = asyncio.create_task(
                    _dispatch_one(redis, handler, stream_id, payload, sem)
                )
                in_flight.add(task)
                task.add_done_callback(in_flight.discard)

    finally:
        # Drain: wait for currently-running handlers before returning so we
        # do not leave a batch mid-ack across a shutdown boundary.
        if in_flight:
            logger.info("webhook worker draining %d in-flight tasks", len(in_flight))
            await asyncio.gather(*in_flight, return_exceptions=True)
        logger.info("webhook worker stopped: consumer=%s", consumer)
