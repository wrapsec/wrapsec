"""
WrapSec — Worker Queue / Scheduler
workers/queue.py

Manages the APScheduler instance that runs background tasks.
Called from api/main.py lifespan to start/stop the scheduler
alongside the FastAPI application.

Usage (in api/main.py lifespan):
    from workers.queue import start_scheduler, stop_scheduler

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await create_tables()
        await start_scheduler()
        yield
        await stop_scheduler()

Schedule configuration (.env):
    RETENTION_WORKER_HOUR   = 2    # Run at 2 AM UTC (default)
    RETENTION_WORKER_MINUTE = 0
    RETENTION_WORKER_ENABLED = true

APScheduler is used because:
  - Integrates natively with asyncio/FastAPI — no separate process
  - Supports cron-style scheduling
  - Handles missed runs gracefully (misfire_grace_time)
  - Lightweight — no Redis or message broker required for simple scheduling
"""

import logging
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.worker_queue")
settings = get_settings()

# Module-level scheduler instance — started once, shared across the app
_scheduler = None


async def start_scheduler() -> None:
    """
    Start the APScheduler background scheduler.
    Called once during FastAPI lifespan startup.
    Safe to call multiple times — will not start a second scheduler.
    """
    global _scheduler

    if not settings.retention_worker_enabled:
        logger.info("Retention worker: disabled via RETENTION_WORKER_ENABLED=false")
        return

    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.cron import CronTrigger
        from workers.tasks import run_retention_cleanup

        _scheduler = AsyncIOScheduler(timezone="UTC")

        _scheduler.add_job(
            func              = run_retention_cleanup,
            trigger           = CronTrigger(
                hour   = settings.retention_worker_hour,
                minute = settings.retention_worker_minute,
            ),
            id                = "retention_cleanup",
            name              = "WrapSec Retention Cleanup",
            misfire_grace_time = 3600,  # Allow up to 1 hour late start (e.g. server restart)
            replace_existing  = True,
            max_instances     = 1,      # Never run two cleanup jobs simultaneously
        )

        _scheduler.start()

        logger.info(
            f"Retention worker: scheduler started — "
            f"runs daily at {settings.retention_worker_hour:02d}:{settings.retention_worker_minute:02d} UTC"
        )

    except ImportError:
        logger.warning(
            "Retention worker: APScheduler not installed — worker disabled. "
            "Install with: pip install apscheduler"
        )
    except Exception as e:
        logger.error(f"Retention worker: failed to start scheduler: {e}")


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
