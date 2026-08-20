# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
What a Scan-All request costs, and whether the configured maximum is sane.

Scanning every message of a conversation turns one request into N detector runs
and N audit appends. The appends are the interesting half: the audit chain is
per-tenant and each row hashes the previous one, so writes are serialised behind
a per-tenant advisory lock held until commit. Concurrent requests from the same
tenant therefore queue, and the queue is N deep per request.

This measures both halves separately so the limit can be chosen on evidence
rather than inherited from the batch endpoint, whose writes do not contend the
same way.

Usage (needs a Postgres with the schema applied):

    DATABASE_URL=postgresql+asyncpg://... python tests/load/scan_all_load.py

Options:
    --messages 1,5,10,20,50     eligible messages per request
    --concurrency 1,4,8         simultaneous requests from ONE tenant
    --requests 10               requests per concurrency level
"""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from db.repositories.audit import AuditRepository
from domain.entities.request import RequestMetadata
from domain.enums import DetectionMode
from services.gateway.fanout import (
    DetectionPolicy,
    ScanItem,
    scan_items,
)
from services.gateway.service import GatewayService

_GATEWAY = GatewayService()

_SAMPLE = (
    "Please summarise the quarterly report and highlight anything unusual "
    "about the vendor payments in the second half."
)


def _percentiles(values: list[float]) -> tuple[float, float, float]:
    if not values:
        return (0.0, 0.0, 0.0)
    ordered = sorted(values)

    def pick(p: float) -> float:
        index = min(len(ordered) - 1, round(p * (len(ordered) - 1)))
        return ordered[index]

    return pick(0.50), pick(0.95), pick(0.99)


async def _one_request(
    session_factory,
    tenant_id: str,
    n_messages: int,
    trace_seed: str,
) -> tuple[float, float, float, int]:
    """
    One Scan-All request: scan N messages, then append N audit rows in order.

    Returns (total_ms, scan_ms, audit_ms, errors). Audit rows are written
    sequentially on purpose -- that is what the proxy does, because the chain
    cannot be built from concurrent writers.
    """
    errors = 0
    started = time.monotonic()

    items = [
        ScanItem(input=f"{_SAMPLE} ({i})", input_source="user_prompt",
                 trace_id=f"{trace_seed}-{i}")
        for i in range(n_messages)
    ]

    scan_started = time.monotonic()
    try:
        scanned = await scan_items(
            items,
            gateway        = _GATEWAY,
            policy         = DetectionPolicy(block_threshold=0.7, sanitize_threshold=0.4),
            detection_mode = DetectionMode.FAST,
            metadata       = RequestMetadata(tenant_id=tenant_id),
        )
    except Exception:
        return (0.0, 0.0, 0.0, n_messages)
    scan_ms = (time.monotonic() - scan_started) * 1000

    audit_started = time.monotonic()
    async with session_factory() as session:
        repo = AuditRepository(session)
        for incoming, result in scanned:
            try:
                await repo.create({
                    "trace_id":         str(incoming.trace_id),
                    "decision":         result.decision.decision.value,
                    "risk_score":       result.decision.risk_score.value,
                    "threats":          [],
                    "input_hash":       "load:" + str(incoming.trace_id),
                    "detection_mode":   "fast",
                    "execution_mode":   "proxy",
                    "llm_invoked":      False,
                    "latency_ms":       1.0,
                    "detection_scores": {},
                    "guardrail_scores": {},
                    "primary_reason":   "NO_THREAT_DETECTED",
                    "confidence":       1.0,
                    "confidence_band":  "HIGH",
                    "input_length":     len(incoming.input),
                    "tenant_id":        tenant_id,
                    "source":           "load",
                    "severity":         "LOW",
                    "input_source":     "user_prompt",
                })
            except Exception:
                errors += 1
    audit_ms = (time.monotonic() - audit_started) * 1000

    return ((time.monotonic() - started) * 1000, scan_ms, audit_ms, errors)


async def _measure(
    session_factory,
    tenant_id: str,
    n_messages: int,
    concurrency: int,
    requests: int,
) -> dict:
    totals: list[float] = []
    scans:  list[float] = []
    audits: list[float] = []
    errors = 0

    semaphore = asyncio.Semaphore(concurrency)

    async def worker(index: int):
        nonlocal errors
        async with semaphore:
            total_ms, scan_ms, audit_ms, failed = await _one_request(
                session_factory, tenant_id, n_messages,
                trace_seed=f"req_{uuid.uuid4().hex}",
            )
            totals.append(total_ms)
            scans.append(scan_ms)
            audits.append(audit_ms)
            errors += failed

    wall_started = time.monotonic()
    await asyncio.gather(*[worker(i) for i in range(requests)])
    wall = time.monotonic() - wall_started

    p50, p95, p99 = _percentiles(totals)
    scanned_messages = requests * n_messages

    return {
        "messages":     n_messages,
        "concurrency":  concurrency,
        "p50":          p50,
        "p95":          p95,
        "p99":          p99,
        "scan_mean":    statistics.fmean(scans)  if scans  else 0.0,
        "audit_mean":   statistics.fmean(audits) if audits else 0.0,
        "audit_per_row": (statistics.fmean(audits) / n_messages) if audits and n_messages else 0.0,
        "throughput":   scanned_messages / wall if wall else 0.0,
        "errors":       errors,
    }


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--messages",    default="1,5,10,20,50")
    parser.add_argument("--concurrency", default="1,4,8")
    parser.add_argument("--requests",    type=int, default=10)
    args = parser.parse_args()

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL is required (a Postgres with the schema applied).")
        return 1

    engine  = create_async_engine(database_url, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    # One tenant on purpose: the chain lock is per tenant, so a single tenant is
    # the contended case and the one the limit has to hold for.
    tenant_id = str(uuid.uuid4())

    message_counts = [int(v) for v in args.messages.split(",")]
    concurrencies  = [int(v) for v in args.concurrency.split(",")]

    print(f"\nScan-All cost, single tenant, {args.requests} requests per point\n")
    print(f"{'msgs':>5} {'conc':>5} {'p50 ms':>9} {'p95 ms':>9} {'p99 ms':>9} "
          f"{'scan ms':>9} {'audit ms':>9} {'ms/row':>8} {'msg/s':>8} {'err':>5}")
    print("-" * 92)

    try:
        for n in message_counts:
            for c in concurrencies:
                row = await _measure(factory, tenant_id, n, c, args.requests)
                print(f"{row['messages']:>5} {row['concurrency']:>5} "
                      f"{row['p50']:>9.1f} {row['p95']:>9.1f} {row['p99']:>9.1f} "
                      f"{row['scan_mean']:>9.1f} {row['audit_mean']:>9.1f} "
                      f"{row['audit_per_row']:>8.1f} {row['throughput']:>8.1f} "
                      f"{row['errors']:>5}")
    finally:
        await engine.dispose()

    print("\nThe audit column is the one that grows with concurrency: chain writes\n"
          "serialise per tenant, so N appends per request queue behind each other.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
