# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec retention cleanup (manual runner).

Thin wrapper around the AUTHORITATIVE retention logic in workers/tasks.py, so the
manual path and the scheduled worker are the same code -- single source of truth.
The worker resolves the audit window PER TENANT (tenant_settings ->
platform_settings -> env) and deletes each tenant's rows against its own window,
plus an orphan pass; proxy raw text is purged deployment-wide. This script does
NOT re-implement any window logic and does not take a --days override, because a
single global window would be wrong in a multi-tenant install (it would apply one
tenant's policy to every tenant's rows -- the bug this delegation removes).

Use it for a one-off run or where the in-process worker cannot run (e.g. cron in
a deployment that does not keep the API process resident). Otherwise the worker
runs this automatically on schedule.

Usage:
  python scripts/cleanup_audit_logs.py                # audit + proxy
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


async def main() -> None:
    parser = argparse.ArgumentParser(description="WrapSec retention cleanup (manual runner)")
    parser.add_argument("--audit-only", action="store_true",
                        help="Only clean audit_logs, skip proxy_interactions")
    parser.add_argument("--proxy-only", action="store_true",
                        help="Only purge proxy_interactions text, skip audit_logs")
    args = parser.parse_args()

    # Delegate to the worker's per-tenant functions -- the authoritative logic.
    from workers.tasks import _cleanup_audit_logs, _cleanup_proxy_interactions

    if not args.proxy_only:
        deleted = await _cleanup_audit_logs()
        logger.info("audit_logs: deleted %d rows (per-tenant windows)", deleted)

    if not args.audit_only:
        purged = await _cleanup_proxy_interactions()
        logger.info("proxy_interactions: purged text from %d rows", purged)


if __name__ == "__main__":
    asyncio.run(main())
