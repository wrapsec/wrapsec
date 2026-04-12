"""
Audit log retention cleanup script.

Deletes audit_logs records older than RETENTION_DAYS (default: 30).
Run this daily via cron or Docker scheduled task.

Usage:
  python scripts/cleanup_audit_logs.py
  python scripts/cleanup_audit_logs.py --days 90
  python scripts/cleanup_audit_logs.py --dry-run
"""
import asyncio
import argparse
import logging
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("wrapsec.cleanup")


async def cleanup(retention_days: int = 30, dry_run: bool = False) -> int:
    """
    Delete audit_logs older than retention_days.
    Returns the number of records deleted (or that would be deleted).
    """
    from db.session import AsyncSessionFactory
    from sqlalchemy import text

    cutoff_sql = f"NOW() - INTERVAL '{retention_days} days'"

    count_query = text(
        f"SELECT COUNT(*) FROM audit_logs WHERE created_at < {cutoff_sql}"
    )
    delete_query = text(
        f"DELETE FROM audit_logs WHERE created_at < {cutoff_sql}"
    )

    async with AsyncSessionFactory() as session:
        # Count records to be deleted
        result = await session.execute(count_query)
        count  = result.scalar()

        logger.info(
            f"Retention policy: {retention_days} days | "
            f"Records to delete: {count} | "
            f"Dry run: {dry_run}"
        )

        if count == 0:
            logger.info("No records to delete — nothing to do")
            return 0

        if dry_run:
            logger.info(f"[DRY RUN] Would delete {count} records")
            return count

        # Delete records
        await session.execute(delete_query)
        await session.commit()

        logger.info(f"Deleted {count} audit log records older than {retention_days} days")
        return count


async def main():
    parser = argparse.ArgumentParser(description="WrapSec audit log retention cleanup")
    parser.add_argument(
        "--days",
        type    = int,
        default = None,
        help    = "Retention period in days (default: from config audit_retention_days)"
    )
    parser.add_argument(
        "--dry-run",
        action  = "store_true",
        help    = "Show what would be deleted without deleting"
    )
    args = parser.parse_args()

    from config.settings import get_settings
    cfg = get_settings()

    if args.days:
        retention_days = args.days
    else:
        # Try to read from DB settings first
        try:
            from db.session import AsyncSessionFactory
            from db.repositories.settings import SettingsRepository
            async with AsyncSessionFactory() as session:
                repo    = SettingsRepository(session)
                stored  = await repo.get("audit_retention")
                if stored and "retention_days" in stored:
                    retention_days = stored["retention_days"]
                    logger.info(f"Using retention from DB: {retention_days} days")
                else:
                    retention_days = cfg.audit_retention_days
                    logger.info(f"Using retention from config: {retention_days} days")
        except Exception as e:
            logger.warning(f"Could not read retention from DB: {e} — using config")
            retention_days = cfg.audit_retention_days

    deleted = await cleanup(
        retention_days = retention_days,
        dry_run        = args.dry_run,
    )

    if args.dry_run:
        logger.info(f"Dry run complete — {deleted} records would be deleted")
    else:
        logger.info(f"Cleanup complete — {deleted} records deleted")


if __name__ == "__main__":
    asyncio.run(main())