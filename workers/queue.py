# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec - Worker Queue / Scheduler
workers/queue.py

Manages the APScheduler instance that runs background tasks.
Called from api/main.py lifespan to start/stop the scheduler
alongside the FastAPI application.

Usage (in api/main.py lifespan):
    from workers.queue import start_scheduler, stop_scheduler

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await run_migrations()
        await start_scheduler()
        yield
        await stop_scheduler()

Schedule configuration (.env):
    RETENTION_WORKER_HOUR   = 2    # Run at 2 AM UTC (default)
    RETENTION_WORKER_MINUTE = 0
    RETENTION_WORKER_ENABLED = true

APScheduler is used because:
  - Integrates natively with asyncio/FastAPI - no separate process
  - Supports cron-style scheduling
  - Handles missed runs gracefully (misfire_grace_time)
  - Lightweight - no Redis or message broker required for simple scheduling
"""

import logging

from config.settings import get_settings

logger = logging.getLogger("wrapsec.worker_queue")

# Module-level scheduler instance - started once, shared across the app
_scheduler = None


async def start_scheduler() -> None:
    """
    Start the APScheduler background scheduler.
    Called once during FastAPI lifespan startup.
    Safe to call multiple times - will not start a second scheduler.

    Registers all in-process scheduled jobs. Each job is gated by its
    own _ENABLED flag so operators can disable individual jobs without
    losing the others.
    """
    global _scheduler

    _settings = get_settings()

    retention_on       = _settings.retention_worker_enabled
    circuit_breaker_on = _settings.webhook_circuit_breaker_enabled

    if not retention_on and not circuit_breaker_on:
        logger.info(
            "Scheduler: all in-process jobs disabled via env - not starting APScheduler"
        )
        return

    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.cron import CronTrigger
        from apscheduler.triggers.interval import IntervalTrigger

        _scheduler = AsyncIOScheduler(timezone="UTC")

        if retention_on:
            from workers.tasks import run_retention_cleanup

            _scheduler.add_job(
                func              = run_retention_cleanup,
                trigger           = CronTrigger(
                    hour   = _settings.retention_worker_hour,
                    minute = _settings.retention_worker_minute,
                ),
                id                = "retention_cleanup",
                name              = "WrapSec Retention Cleanup",
                misfire_grace_time = 3600,  # Allow up to 1 hour late start (e.g. server restart)
                replace_existing  = True,
                max_instances     = 1,      # Never run two cleanup jobs simultaneously
            )
            logger.info(
                f"Retention worker: scheduled daily at "
                f"{_settings.retention_worker_hour:02d}:{_settings.retention_worker_minute:02d} UTC"
            )
        else:
            logger.info("Retention worker: disabled via RETENTION_WORKER_ENABLED=false")

        if circuit_breaker_on:
            from workers.webhook_circuit_breaker import run_circuit_breaker_sweep

            sweep_minutes = _settings.webhook_circuit_breaker_sweep_minutes
            _scheduler.add_job(
                func              = run_circuit_breaker_sweep,
                trigger           = IntervalTrigger(minutes=sweep_minutes),
                id                = "webhook_circuit_breaker",
                name              = "WrapSec Webhook Circuit Breaker Sweep",
                # Grace of one sweep interval: if a worker restart delays the
                # tick, we still catch up on the next boundary rather than
                # skipping the window entirely.
                misfire_grace_time = sweep_minutes * 60,
                replace_existing  = True,
                max_instances     = 1,
            )
            logger.info(
                f"Webhook circuit breaker: scheduled every {sweep_minutes}m, "
                f"grace = {_settings.webhook_circuit_breaker_hours}h"
            )
        else:
            logger.info(
                "Webhook circuit breaker: disabled via WEBHOOK_CIRCUIT_BREAKER_ENABLED=false"
            )

        _scheduler.start()
        logger.info("Scheduler: started")

    except ImportError:
        logger.warning(
            "Scheduler: APScheduler not installed - all jobs disabled. "
            "Install with: pip install apscheduler"
        )
    except Exception as e:
        logger.error(f"Scheduler: failed to start: {e}")


async def stop_scheduler() -> None:
    """
    Stop the scheduler gracefully during FastAPI shutdown.
    Called during lifespan cleanup.
    """
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Retention worker: scheduler stopped")
    _scheduler = None


async def trigger_now() -> None:
    """
    Manually trigger the retention cleanup immediately.
    Used for testing and admin-triggered runs.
    Does not affect the scheduled run.
    """
    from workers.tasks import run_retention_cleanup
    logger.info("Retention worker: manual trigger initiated")
    await run_retention_cleanup()
