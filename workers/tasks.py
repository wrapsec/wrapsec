# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec - Background Retention Worker
workers/tasks.py

Runs the same cleanup logic as scripts/cleanup_audit_logs.py but
automatically on a configurable schedule using APScheduler.

Schedule (configurable via .env):
  RETENTION_WORKER_HOUR   = 2   (run at 2 AM UTC daily)
  RETENTION_WORKER_MINUTE = 0

Started automatically via workers/queue.py which is called from api/main.py
lifespan. Worker runs in-process - no separate process or Celery required.

Design decisions:
  - APScheduler AsyncIOScheduler - integrates cleanly with FastAPI/asyncio
  - Fail-safe: exceptions are caught and logged, never crash the API
  - Idempotent: safe to run multiple times - only deletes/nulls eligible rows
  - Same logic as scripts/cleanup_audit_logs.py - single source of truth
  - Reads retention settings from DB (same as manual script) for consistency
"""

import logging

from services.time import utc_now

logger = logging.getLogger("wrapsec.retention_worker")


RETENTION_LEASE_KEY = "wrapsec:retention:lease"
RETENTION_LEASE_TTL = 3600  # 1 hour - long enough for the cleanup, short
                            # enough that a crash on one worker doesn't block
                            # the next scheduled run 24 hours later.


async def _acquire_retention_lease() -> bool:
    """
    F-5: cross-process lock so only ONE uvicorn worker per install runs the
    retention cleanup per day.

    APScheduler is started in every worker via api/main.py lifespan. Without
    coordination each worker triggers the job at 02:00 UTC and they all race
    on the same DELETE/UPDATE statements. The end state is correct (queries
    are idempotent) but the duplicate DB work is wasted load.

    We use Redis SET NX PX as a lease. TTL is 1 hour - long enough for the
    cleanup to finish on any realistic dataset, short enough that a crashed
    worker never blocks tomorrow's run.

    Fail-open on Redis error: if the lease can't be checked, we let the
    worker run. Worst case is duplicate DB work (the pre-fix behavior).
    NEVER fail-closed here - that would skip cleanup entirely.
    """
    try:
        from cache.redis_client import get_redis
        redis = get_redis()
        acquired = await redis.set(
            RETENTION_LEASE_KEY,
            "held",
            nx = True,
            ex = RETENTION_LEASE_TTL,
        )
        return bool(acquired)
    except Exception as e:
        logger.warning(
            f"Retention worker: lease check failed: {e} - "
            "proceeding without cross-worker coordination"
        )
        return True


async def run_retention_cleanup() -> None:
    """
    Main retention task - runs on schedule.
    Cleans audit_logs, proxy_interactions, and refresh_tokens
    per configured retention periods.
    Never raises - all exceptions are caught and logged.
    """
    # F-5: try to acquire the daily lease. If another worker already holds
    # it, log-and-return; the holder is doing the work. Fail-open if Redis
    # is unavailable (see _acquire_retention_lease docstring).
    if not await _acquire_retention_lease():
        logger.info(
            "Retention worker: another worker holds the daily lease - skipping"
        )
        return

    logger.info("Retention worker: starting scheduled cleanup run")
    start = utc_now()

    try:
        audit_deleted = await _cleanup_audit_logs()
    except Exception as e:
        logger.error(f"Retention worker: audit_logs cleanup failed: {e}")
        audit_deleted = -1

    try:
        proxy_purged = await _cleanup_proxy_interactions()
    except Exception as e:
        logger.error(f"Retention worker: proxy_interactions cleanup failed: {e}")
        proxy_purged = -1

    try:
        tokens_deleted = await _cleanup_refresh_tokens()
    except Exception as e:
        logger.error(f"Retention worker: refresh_tokens cleanup failed: {e}")
        tokens_deleted = -1

    try:
        email_deleted = await _cleanup_email_outbox()
    except Exception as e:
        logger.error(f"Retention worker: email_outbox cleanup failed: {e}")
        email_deleted = -1

    elapsed_ms = int((utc_now() - start).total_seconds() * 1000)

    all_ok = (
        audit_deleted >= 0 and proxy_purged >= 0
        and tokens_deleted >= 0 and email_deleted >= 0
    )

    if all_ok:
        logger.info(
            f"Retention worker: cleanup complete in {elapsed_ms}ms - "
            f"audit_logs deleted: {audit_deleted} | "
            f"proxy_interactions text purged: {proxy_purged} | "
            f"refresh_tokens deleted: {tokens_deleted} | "
            f"email_outbox deleted: {email_deleted}"
        )
    else:
        logger.warning(
            f"Retention worker: cleanup completed with errors in {elapsed_ms}ms - "
            f"audit_logs: {'OK' if audit_deleted >= 0 else 'FAILED'} | "
            f"proxy_interactions: {'OK' if proxy_purged >= 0 else 'FAILED'} | "
            f"refresh_tokens: {'OK' if tokens_deleted >= 0 else 'FAILED'} | "
            f"email_outbox: {'OK' if email_deleted >= 0 else 'FAILED'}"
        )


async def _resolve_audit_retention(session, tenant_id) -> int:
    """
    Audit retention (days) for one tenant: tenant_settings -> platform_settings ->
    env default. A lookup error degrades to the env default rather than skipping
    cleanup for that tenant.
    """
    from config.settings import get_settings
    from db.repositories.settings import (
        PlatformSettingsRepository,
        TenantSettingsRepository,
    )
    try:
        stored = await TenantSettingsRepository(session).get(tenant_id, "audit_retention")
        if stored and "retention_days" in stored:
            return int(stored["retention_days"])
        platform = await PlatformSettingsRepository(session).get("audit_retention")
        if platform and "retention_days" in platform:
            return int(platform["retention_days"])
    except Exception as e:
        logger.warning("Retention worker: retention lookup failed for tenant %s: %s", tenant_id, e)
    return get_settings().audit_retention_days


async def _cleanup_audit_logs() -> int:
    """
    Delete audit_logs older than EACH tenant's retention window (per-tenant, 2.1 --
    enabled by the tenant_id columns). Rows with no tenant attribution are cleaned
    with the deployment default. Returns total rows deleted. DELETE is permitted by
    the audit immutability trigger, which blocks UPDATE only.
    """
    from sqlalchemy import text

    from config.settings import get_settings
    from db.repositories.tenant import TenantRepository
    from db.session import AsyncSessionFactory

    delete_scoped = text(
        "DELETE FROM audit_logs WHERE tenant_id = :tid "
        "AND created_at < NOW() - INTERVAL '1 day' * :days"
    )
    delete_orphan = text(
        "DELETE FROM audit_logs WHERE tenant_id IS NULL "
        "AND created_at < NOW() - INTERVAL '1 day' * :days"
    )

    total = 0
    async with AsyncSessionFactory() as session:
        tenants = await TenantRepository(session).list_all()
        for tenant in tenants:
            days = await _resolve_audit_retention(session, tenant.id)
            if days < 1:
                logger.error("Retention worker: invalid retention_days=%d for tenant %s - skipping",
                             days, tenant.id)
                continue
            res = await session.execute(delete_scoped, {"tid": str(tenant.id), "days": days})
            total += res.rowcount or 0

        # Un-attributed rows (no tenant_id) use the deployment default so nothing
        # is orphaned from cleanup by the per-tenant iteration.
        env_days = get_settings().audit_retention_days
        if env_days >= 1:
            res = await session.execute(delete_orphan, {"days": env_days})
            total += res.rowcount or 0

        await session.commit()

    logger.info("Retention worker: audit_logs - deleted %d rows across %d tenants (+orphans)",
                total, len(tenants))
    return total


async def _cleanup_proxy_interactions() -> int:
    """
    Null out input_raw and output_raw in proxy_interactions rows older than
    the configured proxy retention period.

    Metadata (decisions, scores, threats, latency, execution_status) is
    kept permanently for audit and analytics - only raw text is purged.
    """
    from sqlalchemy import text

    from config.settings import get_settings
    from db.session import AsyncSessionFactory

    cfg            = get_settings()
    retention_days = cfg.data_retention_days_proxy
    if retention_days < 1:
        logger.error(f"Retention worker: invalid data_retention_days_proxy={retention_days} - must be >= 1, skipping proxy cleanup")
        return 0

    count_query = text("""
        SELECT COUNT(*)
        FROM proxy_interactions
        WHERE created_at < NOW() - INTERVAL '1 day' * :days
          AND (input_raw IS NOT NULL OR output_raw IS NOT NULL)
    """)

    purge_query = text("""
        UPDATE proxy_interactions
        SET input_raw  = NULL,
            output_raw = NULL
        WHERE created_at < NOW() - INTERVAL '1 day' * :days
          AND (input_raw IS NOT NULL OR output_raw IS NOT NULL)
    """)

    async with AsyncSessionFactory() as session:
        result = await session.execute(count_query, {"days": retention_days})
        count  = result.scalar() or 0

        if count == 0:
            logger.info(
                f"Retention worker: proxy_interactions - nothing to purge "
                f"(retention: {retention_days} days)"
            )
            return 0

        await session.execute(purge_query, {"days": retention_days})
        await session.commit()

        logger.info(
            f"Retention worker: proxy_interactions - purged input_raw/output_raw "
            f"from {count} rows older than {retention_days} days (metadata retained)"
        )
        return count


async def _cleanup_email_outbox() -> int:
    """
    Delete email_outbox rows older than the configured retention period.
    Returns count of rows deleted.

    Email rows carry no secrets, but they hold recipient addresses (personal
    data), so they are not retained indefinitely. All statuses are purged by
    age: terminal rows (provider_accepted / failed) and any long-stale queued
    rows alike. Retention is the admin-managed email setting (DB), falling back
    to the env default -- the same pattern as audit retention.
    """
    from sqlalchemy import text

    from db.session import AsyncSessionFactory
    from services.email.settings import get_email_settings

    async with AsyncSessionFactory() as session:
        retention_days = (await get_email_settings(session)).retention_days
    if retention_days < 1:
        logger.error(
            f"Retention worker: invalid email_retention_days={retention_days} - "
            "must be >= 1, skipping email cleanup"
        )
        return 0

    count_query  = text("SELECT COUNT(*) FROM email_outbox WHERE created_at < NOW() - INTERVAL '1 day' * :days")
    delete_query = text("DELETE FROM email_outbox WHERE created_at < NOW() - INTERVAL '1 day' * :days")

    async with AsyncSessionFactory() as session:
        result = await session.execute(count_query, {"days": retention_days})
        count  = result.scalar() or 0

        if count == 0:
            logger.info(
                f"Retention worker: email_outbox - nothing to delete "
                f"(retention: {retention_days} days)"
            )
            return 0

        await session.execute(delete_query, {"days": retention_days})
        await session.commit()

        logger.info(
            f"Retention worker: email_outbox - deleted {count} rows "
            f"older than {retention_days} days"
        )
        return count


async def _cleanup_refresh_tokens() -> int:
    """
    Deletes expired refresh tokens using two clauses.

    Clause 1 (primary - preserves recent audit trail):
        DELETE WHERE expires_at < NOW() AND revoked_at IS NOT NULL
        Keeps: expired-but-active (failed naturally, audit value remains)
        Keeps: revoked-but-not-expired (recent termination, investigation value)
        Deletes: BOTH expired AND explicitly revoked - audit value exhausted.

    Clause 2 (secondary - prevents unbounded table growth):
        DELETE WHERE expires_at < NOW() - 90 days
        Deletes ALL tokens older than 3x the refresh token lifetime (30 days).
        Covers users who abandoned sessions without ever logging out.
        At 90 days, audit value is exhausted regardless of revocation state.

    Combined: no token older than 90 days survives.
    Returns total deleted rows from both clauses combined.
    """
    from db.repositories.refresh_token import RefreshTokenRepository
    from db.session import AsyncSessionFactory

    async with AsyncSessionFactory() as session:
        repo    = RefreshTokenRepository(session)
        deleted = await repo.cleanup_expired()
        await session.commit()

    logger.info(f"Retention worker: refresh_tokens - deleted {deleted} expired rows")
    return deleted
