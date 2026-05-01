# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec — Background Retention Worker
workers/tasks.py

Runs the same cleanup logic as scripts/cleanup_audit_logs.py but
automatically on a configurable schedule using APScheduler.

Schedule (configurable via .env):
  RETENTION_WORKER_HOUR   = 2   (run at 2 AM UTC daily)
  RETENTION_WORKER_MINUTE = 0

Started automatically via workers/queue.py which is called from api/main.py
lifespan. Worker runs in-process — no separate process or Celery required.

Design decisions:
  - APScheduler AsyncIOScheduler — integrates cleanly with FastAPI/asyncio
  - Fail-safe: exceptions are caught and logged, never crash the API
  - Idempotent: safe to run multiple times — only deletes/nulls eligible rows
  - Same logic as scripts/cleanup_audit_logs.py — single source of truth
  - Reads retention settings from DB (same as manual script) for consistency
"""

import logging
from datetime import datetime

logger = logging.getLogger("wrapsec.retention_worker")


async def run_retention_cleanup() -> None:
    """
    Main retention task — runs on schedule.
    Cleans audit_logs, proxy_interactions, and refresh_tokens
    per configured retention periods.
    Never raises — all exceptions are caught and logged.
    """
    logger.info("Retention worker: starting scheduled cleanup run")
    start = datetime.utcnow()

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

    elapsed_ms = int((datetime.utcnow() - start).total_seconds() * 1000)

    all_ok = audit_deleted >= 0 and proxy_purged >= 0 and tokens_deleted >= 0

    if all_ok:
        logger.info(
            f"Retention worker: cleanup complete in {elapsed_ms}ms — "
            f"audit_logs deleted: {audit_deleted} | "
            f"proxy_interactions text purged: {proxy_purged} | "
            f"refresh_tokens deleted: {tokens_deleted}"
        )
    else:
        logger.warning(
            f"Retention worker: cleanup completed with errors in {elapsed_ms}ms — "
            f"audit_logs: {'OK' if audit_deleted >= 0 else 'FAILED'} | "
            f"proxy_interactions: {'OK' if proxy_purged >= 0 else 'FAILED'} | "
            f"refresh_tokens: {'OK' if tokens_deleted >= 0 else 'FAILED'}"
        )


async def _resolve_audit_retention() -> int:
    """
    Read audit retention from DB settings (same as manual script).
    Falls back to config if DB is unavailable.
    """
    try:
        from db.session import AsyncSessionFactory
        from db.repositories.settings import SettingsRepository
        from config.settings import get_settings
        cfg = get_settings()

        async with AsyncSessionFactory() as session:
            repo   = SettingsRepository(session)
            stored = await repo.get("audit_retention")
            if stored and "retention_days" in stored:
                days = int(stored["retention_days"])
                logger.debug(f"Retention worker: audit retention from DB: {days} days")
                return days

        return cfg.audit_retention_days

    except Exception as e:
        from config.settings import get_settings
        cfg = get_settings()
        logger.warning(
            f"Retention worker: could not read audit retention from DB: {e} "
            f"— using config default ({cfg.audit_retention_days} days)"
        )
        return cfg.audit_retention_days


async def _cleanup_audit_logs() -> int:
    """
    Delete audit_logs rows older than the configured retention period.
    Returns count of rows deleted.
    """
    from db.session import AsyncSessionFactory
    from sqlalchemy import text

    retention_days = await _resolve_audit_retention()
    if retention_days < 1:
        logger.error(f"Retention worker: invalid retention_days={retention_days} — must be >= 1, skipping audit cleanup")
        return 0
    cutoff_sql     = f"NOW() - INTERVAL '{retention_days} days'"

    count_query  = text(f"SELECT COUNT(*) FROM audit_logs WHERE created_at < {cutoff_sql}")
    delete_query = text(f"DELETE FROM audit_logs WHERE created_at < {cutoff_sql}")

    async with AsyncSessionFactory() as session:
        result = await session.execute(count_query)
        count  = result.scalar() or 0

        if count == 0:
            logger.info(
                f"Retention worker: audit_logs — nothing to delete "
                f"(retention: {retention_days} days)"
            )
            return 0

        await session.execute(delete_query)
        await session.commit()

        logger.info(
            f"Retention worker: audit_logs — deleted {count} rows "
            f"older than {retention_days} days"
        )
        return count


async def _cleanup_proxy_interactions() -> int:
    """
    Null out input_raw and output_raw in proxy_interactions rows older than
    the configured proxy retention period.

    Metadata (decisions, scores, threats, latency, execution_status) is
    kept permanently for audit and analytics — only raw text is purged.
    """
    from db.session import AsyncSessionFactory
    from config.settings import get_settings
    from sqlalchemy import text

    cfg            = get_settings()
    retention_days = cfg.data_retention_days_proxy
    if retention_days < 1:
        logger.error(f"Retention worker: invalid data_retention_days_proxy={retention_days} — must be >= 1, skipping proxy cleanup")
        return 0
    cutoff_sql     = f"NOW() - INTERVAL '{retention_days} days'"

    count_query = text(f"""
        SELECT COUNT(*)
        FROM proxy_interactions
        WHERE created_at < {cutoff_sql}
          AND (input_raw IS NOT NULL OR output_raw IS NOT NULL)
    """)

    purge_query = text(f"""
        UPDATE proxy_interactions
        SET input_raw  = NULL,
            output_raw = NULL
        WHERE created_at < {cutoff_sql}
          AND (input_raw IS NOT NULL OR output_raw IS NOT NULL)
    """)

    async with AsyncSessionFactory() as session:
        result = await session.execute(count_query)
        count  = result.scalar() or 0

        if count == 0:
            logger.info(
                f"Retention worker: proxy_interactions — nothing to purge "
                f"(retention: {retention_days} days)"
            )
            return 0

        await session.execute(purge_query)
        await session.commit()

        logger.info(
            f"Retention worker: proxy_interactions — purged input_raw/output_raw "
            f"from {count} rows older than {retention_days} days (metadata retained)"
        )
        return count


async def _cleanup_refresh_tokens() -> int:
    """
    Deletes expired refresh tokens using two clauses.

    Clause 1 (primary — preserves recent audit trail):
        DELETE WHERE expires_at < NOW() AND revoked_at IS NOT NULL
        Keeps: expired-but-active (failed naturally, audit value remains)
        Keeps: revoked-but-not-expired (recent termination, investigation value)
        Deletes: BOTH expired AND explicitly revoked — audit value exhausted.

    Clause 2 (secondary — prevents unbounded table growth):
        DELETE WHERE expires_at < NOW() - 90 days
        Deletes ALL tokens older than 3x the refresh token lifetime (30 days).
        Covers users who abandoned sessions without ever logging out.
        At 90 days, audit value is exhausted regardless of revocation state.

    Combined: no token older than 90 days survives.
    Returns total deleted rows from both clauses combined.
    """
    from db.session import AsyncSessionFactory
    from db.repositories.refresh_token import RefreshTokenRepository

    async with AsyncSessionFactory() as session:
        repo    = RefreshTokenRepository(session)
        deleted = await repo.cleanup_expired()
        await session.commit()

    logger.info(f"Retention worker: refresh_tokens — deleted {deleted} expired rows")
    return deleted
