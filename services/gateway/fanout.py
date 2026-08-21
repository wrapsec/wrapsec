# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Run the detection pipeline over several inputs from one HTTP request.

Two callers need this: the batch scan endpoint, and the proxy when it scans more
than one message of a conversation. Both need identical resource behaviour, so it
lives here rather than being written twice.

What this module owns:

  * bounded concurrency, so one request cannot spawn unbounded detector work;
  * rate-limit accounting for the extra units a multi-input request consumes;
  * ordered results, so a caller can zip them back against its own inputs.

What this module deliberately does NOT own:

  * persistence. Callers write their own audit rows, and they must do so
    SEQUENTIALLY. Scans run concurrently, but the audit hash chain is per-tenant
    and each row hashes the previous row, so concurrent writes would contend on
    the chain. Scan wide, persist in order.
  * response shaping and aggregation. A batch reports per-item results and
    counters; a proxy reduces to one decision. Those are genuinely different and
    belong to the caller.
"""

from __future__ import annotations

import asyncio
import logging
import weakref
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any

from config.settings import get_settings
from domain.entities.request import IncomingRequest, RequestMetadata
from domain.enums import DetectionMode, ExecutionMode
from domain.value_objects.trace_id import TraceId
from errors.exceptions import RateLimitError
from services.gateway.service import GatewayService

logger = logging.getLogger("wrapsec.gateway.fanout")


@dataclass(frozen=True)
class DetectionPolicy:
    """
    The resolved detection knobs shared by every input in one request.

    Policy resolves once per request: the whole set shares the caller's
    tenant/department/application scope, so per-input resolution would be both
    wasteful and wrong.
    """

    block_threshold:             float
    sanitize_threshold:          float
    pii_block_threshold:         float | None = None
    pii_sanitize_threshold:      float | None = None
    toxicity_block_threshold:    float | None = None
    toxicity_sanitize_threshold: float | None = None
    rule_enabled:                bool = True
    ml_enabled:                  bool = True
    llm_enabled:                 bool = True
    llm_settings:                dict | None = None


@dataclass(frozen=True)
class ScanItem:
    """
    One unit of work.

    `input_source` is per-item on purpose: a single request can mix trust levels
    (a user turn and retrieved content), and each scan must carry its own
    provenance rather than inheriting one classification for the whole set.

    `trace_id` lets a caller supply its own identifier. `audit_logs.trace_id` is
    unique, so a caller writing several rows for one request must derive a
    distinct id per item; leaving this None generates an independent one.
    """

    input:        str
    input_source: str
    trace_id:     str | None = None


async def charge_additional_units(request: Any, n: int) -> None:
    """
    Charge the rate-limit bucket for the extra units a multi-input request uses.

    The middleware already consumed one slot for the HTTP request itself, so only
    the remaining n-1 are charged here. Fails open when the store is unavailable,
    matching the limiter elsewhere: a rate-limit outage must not deny traffic.

    Raises RateLimitError when the bucket is exhausted.
    """
    if n <= 1:
        return

    from cache.rate_limit_store import is_rate_limited

    # The identifier the ENFORCING limiter used for this request, published by
    # it. Deriving a second one here is what made these units land in a bucket
    # nothing reads: the limiter buckets on a hash of the presented key, while
    # request.state.key_id is the key record's id and already prefixed.
    # Absent attribute and None mean different things: the first is a broken
    # contract, the second is limiting that does not apply to this path.
    if not hasattr(request.state, "rate_limit_id"):
        # The limiter runs ahead of every path that reaches here, so its absence
        # means the contract was broken rather than that limiting was skipped.
        # Loud, because the symptom otherwise is silently unmetered fan-out.
        logger.error(
            "No rate-limit identifier on the request; %d additional units were "
            "not charged. The rate-limit middleware must publish one.", n - 1,
        )
        return

    rate_limit_id = request.state.rate_limit_id
    if rate_limit_id is None:
        return  # Limiting is off, or does not cover this path. Nothing to charge.

    # No broad exception handling here. The store already fails open on its own
    # outages, logging as it does so, which is the only failure this had any
    # business absorbing. Catching more would hide the caller's own defects --
    # and did: it swallowed the wrong-bucket bug above for as long as it existed.
    is_limited, _, _ = await is_rate_limited(rate_limit_id, cost=n - 1)
    if is_limited:
        raise RateLimitError()


# One bound on detector work for the whole process, not one per request.
#
# A semaphore built per call bounds the request that built it and nothing else,
# so N concurrent multi-input requests ran up to N x the limit of detector tasks
# between them. Under that load detectors exceed their timeout, and detection
# failure is fail-closed, so the result was legitimate traffic refused with a
# BLOCK indistinguishable from one caused by its content.
#
# Keyed by event loop and built lazily. A semaphore created at import binds to
# whichever loop is running then, and awaiting it from another loop raises --
# the normal case under a test runner that gives each test a fresh loop. The
# loop is a weak key, so a finished loop's entry goes with it. The limit is a
# setting and can change between calls, so each value gets its own semaphore
# rather than a stale capacity being reused.
_LIMITERS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _process_limiter(limit: int) -> asyncio.Semaphore:
    loop     = asyncio.get_running_loop()
    per_loop = _LIMITERS.setdefault(loop, {})
    sem      = per_loop.get(limit)
    if sem is None:
        sem = asyncio.Semaphore(max(1, limit))
        per_loop[limit] = sem
    return sem


async def scan_items(
    items:          list[ScanItem],
    *,
    gateway:        GatewayService,
    policy:         DetectionPolicy,
    detection_mode: DetectionMode,
    metadata:       RequestMetadata,
    execution_mode: ExecutionMode = ExecutionMode.SCAN_ONLY,
    concurrency:    int | None = None,
) -> list[tuple[IncomingRequest, Any]]:
    """
    Run the pipeline over every item, bounded by `concurrency`.

    Returns `(IncomingRequest, result)` pairs in the SAME ORDER as `items`, so a
    caller can zip them against its own inputs. Order is guaranteed by gather,
    not by completion time.

    Every call is bounded by the process-wide limit (`batch_concurrency`), which
    is shared with every other call in flight. That is what stops N concurrent
    requests from running N times the limit of detector tasks between them.

    `concurrency` applies an ADDITIONAL bound to this call only. It can tighten
    what one call runs; it cannot loosen the process-wide bound, so a caller
    cannot use it to buy more detector capacity than the process allows.
    """
    shared = _process_limiter(get_settings().batch_concurrency)
    local  = asyncio.Semaphore(max(1, concurrency)) if concurrency is not None else None

    async def _scan(item: ScanItem) -> tuple[IncomingRequest, Any]:
        async with AsyncExitStack() as stack:
            # Same order for every task, so the two can never deadlock against
            # each other.
            await stack.enter_async_context(shared)
            if local is not None:
                await stack.enter_async_context(local)
            # A supplied id is taken as-is; deriving it correctly (uniqueness and
            # the audit column's width) belongs to the caller that owns the
            # request-level identifier.
            trace_id = TraceId(item.trace_id) if item.trace_id else TraceId.generate()
            incoming = IncomingRequest(
                input          = item.input,
                trace_id       = trace_id,
                detection_mode = detection_mode,
                execution_mode = execution_mode,
                input_source   = item.input_source,
                metadata       = metadata,
            )
            result = await gateway.process(
                incoming,
                policy.block_threshold,
                policy.sanitize_threshold,
                policy.pii_block_threshold,
                policy.pii_sanitize_threshold,
                policy.toxicity_block_threshold,
                policy.toxicity_sanitize_threshold,
                policy.rule_enabled,
                policy.ml_enabled,
                policy.llm_enabled,
                policy.llm_settings,
            )
            return incoming, result

    return list(await asyncio.gather(*[_scan(item) for item in items]))
