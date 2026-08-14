# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec retention cleanup script.

Deletes records older than configured retention periods:
  - audit_logs:          RETENTION_DAYS (default: 30, from DB or config)
  - proxy_interactions:  DATA_RETENTION_DAYS_PROXY (default: 7, from config)
    Note: only input_raw and output_raw are deleted from proxy_interactions
    (nulled out). All metadata, decisions, and scores are kept permanently.

Run this daily via cron or Docker scheduled task.

Usage:
  python scripts/cleanup_audit_logs.py
  python scripts/cleanup_audit_logs.py --days 90
  python scripts/cleanup_audit_logs.py --proxy-days 14
  python scripts/cleanup_audit_logs.py --dry-run
  python scripts/cleanup_audit_logs.py --audit-only
  python scripts/cleanup_audit_logs.py --proxy-only
"""
import argparse
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("wrapsec.cleanup")


async def cleanup_audit_logs(retention_days: int = 30, dry_run: bool = False) -> int:
    """
    Delete audit_logs rows older than retention_days.
    Returns count of rows deleted (or that would be deleted).
    """
    from sqlalchemy import text

    from db.session import AsyncSessionFactory

    if retention_days < 1:
        raise ValueError(f"retention_days must be >= 1, got {retention_days}")

    count_query  = text("SELECT COUNT(*) FROM audit_logs WHERE created_at < NOW() - INTERVAL '1 day' * :days")
    delete_query = text("DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '1 day' * :days")

    async with AsyncSessionFactory() as session:
        result = await session.execute(count_query, {"days": retention_days})
        count  = result.scalar()

        logger.info(
            f"[audit_logs] Retention: {retention_days} days | "
            f"Rows to delete: {count} | Dry run: {dry_run}"
        )

        if count == 0:
            logger.info("[audit_logs] Nothing to delete")
            return 0

        if dry_run:
            logger.info(f"[audit_logs] [DRY RUN] Would delete {count} rows")
            return count

        await session.execute(delete_query, {"days": retention_days})
        await session.commit()
        logger.info(f"[audit_logs] Deleted {count} rows older than {retention_days} days")
        return count


async def cleanup_proxy_interactions(retention_days: int = 7, dry_run: bool = False) -> int:
    """
    Null out input_raw and output_raw in proxy_interactions rows older than
    retention_days. All other fields (decisions, scores, threats, latency,
    execution_status) are kept permanently for audit and analytics purposes.

    This approach satisfies data minimisation requirements while preserving
    the security audit trail -- you know what happened but not the raw content.

    Returns count of rows updated (or that would be updated).
    """
    from sqlalchemy import text

    from db.session import AsyncSessionFactory

    if retention_days < 1:
        raise ValueError(f"retention_days must be >= 1, got {retention_days}")

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
        count  = result.scalar()

        logger.info(
            f"[proxy_interactions] Retention: {retention_days} days | "
            f"Rows to purge text from: {count} | Dry run: {dry_run}"
        )

        if count == 0:
            logger.info("[proxy_interactions] Nothing to purge")
            return 0

        if dry_run:
            logger.info(f"[proxy_interactions] [DRY RUN] Would null input_raw/output_raw in {count} rows")
            return count

        await session.execute(purge_query, {"days": retention_days})
        await session.commit()
        logger.info(
            f"[proxy_interactions] Purged input_raw/output_raw from {count} rows "
            f"older than {retention_days} days (metadata retained)"
        )
        return count


async def main():
    parser = argparse.ArgumentParser(description="WrapSec retention cleanup")
    parser.add_argument(
        "--days",
        type    = int,
        default = None,
        help    = "audit_logs retention in days (default: from DB or config)"
    )
    parser.add_argument(
        "--proxy-days",
        type    = int,
        default = None,
        help    = "proxy_interactions text retention in days (default: from config)"
    )
    parser.add_argument(
        "--dry-run",
        action = "store_true",
        help   = "Show what would be purged without making changes"
    )
    parser.add_argument(
        "--audit-only",
        action = "store_true",
        help   = "Only clean audit_logs, skip proxy_interactions"
    )
    parser.add_argument(
        "--proxy-only",
        action = "store_true",
        help   = "Only clean proxy_interactions, skip audit_logs"
    )
    args = parser.parse_args()

    from config.settings import get_settings
    cfg = get_settings()

    # -- Resolve audit_logs retention --
    if args.days:
        audit_retention = args.days
        logger.info(f"Using audit retention from CLI: {audit_retention} days")
    else:
        try:
            from db.repositories.settings import TenantSettingsRepository
            from db.repositories.tenant import TenantRepository
            from db.session import AsyncSessionFactory
            async with AsyncSessionFactory() as session:
                # v1 single-tenant: the default tenant's retention (per-tenant is Phase 2).
                tenant = await TenantRepository(session).get_default()
                stored = await TenantSettingsRepository(session).get(tenant.id, "audit_retention") if tenant else None
                if stored and "retention_days" in stored:
                    audit_retention = stored["retention_days"]
                    logger.info(f"Using audit retention from DB: {audit_retention} days")
                else:
                    audit_retention = cfg.audit_retention_days
                    logger.info(f"Using audit retention from config: {audit_retention} days")
        except Exception as e:
            logger.warning(f"Could not read audit retention from DB: {e} -- using config")
            audit_retention = cfg.audit_retention_days

    # -- Resolve proxy_interactions retention --
    proxy_retention = args.proxy_days if args.proxy_days is not None else cfg.data_retention_days_proxy
    logger.info(f"Using proxy retention from config: {proxy_retention} days")

    # -- Run cleanup --
    total_audit = 0
    total_proxy = 0

    if not args.proxy_only:
        total_audit = await cleanup_audit_logs(
            retention_days = audit_retention,
            dry_run        = args.dry_run,
        )

    if not args.audit_only:
        total_proxy = await cleanup_proxy_interactions(
            retention_days = proxy_retention,
            dry_run        = args.dry_run,
        )

    if args.dry_run:
        logger.info(
            f"Dry run complete -- "
            f"audit_logs: {total_audit} rows would be deleted | "
            f"proxy_interactions: {total_proxy} rows would have text purged"
        )
    else:
        logger.info(
            f"Cleanup complete -- "
            f"audit_logs: {total_audit} rows deleted | "
            f"proxy_interactions: {total_proxy} rows text purged"
        )


if __name__ == "__main__":
    asyncio.run(main())