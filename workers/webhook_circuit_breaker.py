# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Webhook circuit-breaker sweep worker (v1.3.0).

APScheduler entry point that periodically flips `disabled = True` on
every webhook endpoint whose `first_failure_at` timer has exceeded the
configured grace window (default 120h, see
services/webhooks/circuit_breaker.py).

Why a sweep rather than an inline check in the delivery handler:

  * A dead endpoint may never see another delivery attempt -- once its
    in-flight messages exhaust their retry schedule and DLQ, no code
    path will fire again for that endpoint. An inline check would
    leave `disabled = False` on abandoned URLs forever.

  * Separation of concerns matches the industry pattern (Svix,
    Hookdeck): delivery decides SUCCESS/RETRY/DLQ, lifecycle decides
    ENABLED/DISABLED. The two loops can be tuned and reasoned about
    independently.

Cross-worker safety: uses the same Redis-lease pattern as the
retention worker so multiple uvicorn workers on the same install do
not race on the same UPDATE. Fail-open on Redis error so a Redis
outage does not silently freeze the circuit breaker.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("wrapsec.webhook_circuit_breaker")


CIRCUIT_BREAKER_LEASE_KEY = "wrapsec:webhook:circuit_breaker:lease"
CIRCUIT_BREAKER_LEASE_TTL = 600   # 10 minutes -- long enough for the
                                  # sweep to finish, short enough that
                                  # a crashed worker only blocks one
                                  # tick, not the whole cadence.


async def _acquire_lease() -> bool:
    """
    Try to become the single worker that runs this tick's sweep.

    Same pattern as workers/tasks._acquire_retention_lease: SET NX PX
    on a Redis key with a bounded TTL. Fail-open on any Redis error --
    duplicate DB writes are strictly better than never sweeping at all
    (the query is idempotent, so the worst case is wasted work).
    """
    try:
        from cache.redis_client import get_redis
        redis = get_redis()
        acquired = await redis.set(
            CIRCUIT_BREAKER_LEASE_KEY,
            "held",
            nx = True,
            ex = CIRCUIT_BREAKER_LEASE_TTL,
        )
        return bool(acquired)
    except Exception as exc:
        logger.warning(
            "webhook circuit breaker: lease check failed: %s -- "
            "proceeding without cross-worker coordination", exc,
        )
        return True


async def run_circuit_breaker_sweep() -> None:
    """
    One sweep tick. Wired to APScheduler in workers/queue.py.

    Never raises: an exception here would stop the scheduled job
    silently on some APScheduler configurations, and the sweep must
    keep running even if a single tick fails. Errors are logged.
    """
    if not await _acquire_lease():
        logger.debug(
            "webhook circuit breaker: another worker holds the tick lease -- skipping",
        )
        return

    try:
        from config.settings import get_settings
        from db.repositories.webhook_endpoint import WebhookEndpointRepository
        from db.session import AsyncSessionFactory

        threshold_h = get_settings().webhook_circuit_breaker_hours

        async with AsyncSessionFactory() as db:
            repo    = WebhookEndpointRepository(db)
            flipped = await repo.disable_stale(threshold_hours=threshold_h)
            await db.commit()

        if flipped:
            logger.warning(
                "webhook circuit breaker: disabled %d endpoints past %dh grace: %s",
                len(flipped), threshold_h,
                [str(ep_id) for ep_id in flipped],
            )
        else:
            logger.debug(
                "webhook circuit breaker: no endpoints past %dh grace this tick",
                threshold_h,
            )
    except Exception:
        logger.exception(
            "webhook circuit breaker: sweep failed",
        )
