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
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum

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
    Consumer name identifying this worker in the Redis consumer group.

    A STABLE name per replica (env WRAPSEC_WEBHOOK_CONSUMER, else hostname:pid)
    matters: on restart the same name lets the process re-read its OWN pending
    entries (read_own_pending) that a mid-delivery crash/cancel stranded.
    `hostname:pid` changes across restarts, so a pod that keeps its identity
    (a StatefulSet replica ordinal, say) should set the env var; otherwise those
    entries are recovered only later by another worker via XAUTOCLAIM.
    """
    override = os.getenv("WRAPSEC_WEBHOOK_CONSUMER")
    return override if override else f"{socket.gethostname()}:{os.getpid()}"


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
        except Exception:
            logger.exception(
                "webhook handler raised, requeueing with 60s backoff"
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
            # Bump attempt_number so the next delivery consumes the next retry
            # slot -- without this the schedule never advances and the message
            # retries forever instead of exhausting into the DLQ.
            requeued = {**payload, "attempt_number": int(payload.get("attempt_number", 1)) + 1}
            await webhook_queue.enqueue_delayed(redis, requeued, run_at)
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
    redis:             Redis,
    handler:           DeliveryHandler,
    consumer:          str | None = None,
    stop_event:        asyncio.Event | None = None,
    concurrency:       int = 8,
    batch:             int = 10,
    poll_block_ms:     int = 5000,
    claim_min_idle_ms: int = 60000,
) -> None:
    """
    Worker main loop. Runs until `stop_event` is set (or forever if None).

    Call from a supervisor coroutine (e.g. FastAPI lifespan) with an
    asyncio.Event you can .set() on shutdown. The loop returns cleanly after
    the current batch drains -- in-flight handlers are awaited via the
    semaphore before return so no delivery is orphaned mid-flight.

    Crash recovery (H1): at startup this consumer drains its OWN pending entries
    (stranded by a previous mid-delivery crash/cancel), and each iteration runs an
    XAUTOCLAIM pass to reclaim entries a DEAD replica left idle longer than
    `claim_min_idle_ms`. That timeout must exceed the worst-case single delivery
    so a slow-but-alive worker's in-flight entry is never reclaimed (double send).
    """
    if consumer is None:
        consumer = default_consumer_name()
    if stop_event is None:
        stop_event = asyncio.Event()

    await webhook_queue.ensure_consumer_group(redis)

    sem     = asyncio.Semaphore(concurrency)
    in_flight: set[asyncio.Task] = set()

    def _spawn(stream_id: str, payload: dict) -> None:
        task = asyncio.create_task(_dispatch_one(redis, handler, stream_id, payload, sem))
        in_flight.add(task)
        task.add_done_callback(in_flight.discard)

    logger.info("webhook worker started: consumer=%s concurrency=%d", consumer, concurrency)

    # Startup recovery: reclaim THIS consumer's own PEL -- entries delivered but
    # not acked before the previous process exited. Needs the stable consumer name.
    try:
        recovered = await webhook_queue.read_own_pending(redis, consumer)
        if recovered:
            logger.info("webhook worker recovering %d own-PEL entries at startup", len(recovered))
        for stream_id, payload in recovered:
            _spawn(stream_id, payload)
    except Exception:
        logger.exception("own-PEL startup drain failed")

    try:
        while not stop_event.is_set():
            # Move any due retries into the main stream first so the same
            # XREADGROUP call can pick them up alongside fresh entries.
            try:
                await webhook_queue.promote_delayed(redis)
            except Exception:
                logger.exception("promote_delayed failed")

            # Reclaim entries stranded by a DEAD replica (idle > visibility
            # timeout) so they are re-delivered instead of lost forever.
            try:
                for stream_id, payload in await webhook_queue.claim_stale(
                    redis, consumer, claim_min_idle_ms,
                ):
                    _spawn(stream_id, payload)
            except Exception:
                logger.exception("claim_stale (XAUTOCLAIM) failed")

            try:
                entries = await webhook_queue.read(
                    redis,
                    consumer  = consumer,
                    count     = batch,
                    block_ms  = poll_block_ms,
                )
            except Exception:
                logger.exception("XREADGROUP failed, backing off 1s")
                await asyncio.sleep(1.0)
                continue

            for stream_id, payload in entries:
                _spawn(stream_id, payload)

    finally:
        # Drain: wait for currently-running handlers before returning so we
        # do not leave a batch mid-ack across a shutdown boundary.
        if in_flight:
            logger.info("webhook worker draining %d in-flight tasks", len(in_flight))
            await asyncio.gather(*in_flight, return_exceptions=True)
        logger.info("webhook worker stopped: consumer=%s", consumer)
