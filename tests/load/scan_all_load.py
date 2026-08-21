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

MEASURE THE BUILD YOU RUN. The Tier-2 transformer ships only in the optional
build, and it dominates this measurement: with it the detectors contend for CPU
and time out, and fail-closed turns each timeout into a BLOCK the caller cannot
tell from a content block. Without it the same load produces none. Measuring a
development machine that happens to have Tier 2 installed would report a cost
most deployments never pay, and would tune the timeouts against the wrong shape.

Usage (needs a Postgres with the schema applied):

    DATABASE_URL=postgresql+asyncpg://... python tests/load/scan_all_load.py
    DATABASE_URL=... python tests/load/scan_all_load.py --no-transformer

Options:
    --messages 1,5,10,20,50     eligible messages per request
    --concurrency 1,4,8         simultaneous requests from ONE tenant
    --requests 10               requests per concurrency level
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import logging
import os
import statistics
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# --no-transformer has to be handled before the gateway is imported, because the
# Tier-2 detector loads its model at construction. Blocking the import makes it
# fail to load and degrade, which is exactly the state of a default deployment:
# the transformer ships only in the optional build (BUILD_ENV=transformer), so
# measuring a dev box that happens to have it installed would report a cost most
# deployments do not pay, and would tune the timeouts against the wrong shape.
if "--no-transformer" in sys.argv:
    sys.modules["transformers"] = None  # type: ignore[assignment]

from sqlalchemy import text
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


# Which detector timed out, counted from the log the pipeline already emits.
#
# The timeout is not reported on the result -- the pipeline swaps in a clean
# result and records the failure by logging it -- so the log is the only place
# that says WHICH detector gave up. Without that, a timeout-induced block is
# indistinguishable from a content block in the numbers, and the tuning question
# ("which detector needs more time, or less work") has no answer.
_TIMEOUT_SOURCES = {
    "Input guard timeout":   "input_guard",
    "Rule detector timeout": "rule_detector",
    "ML pipeline timeout":   "ml_pipeline",
    "Transformer inference": "transformer",
}


class _TimeoutCounter(logging.Handler):
    """Counts detector-timeout log lines by source, for the run's duration."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.counts: collections.Counter[str] = collections.Counter()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:
            return
        for needle, source in _TIMEOUT_SOURCES.items():
            if needle in message:
                self.counts[source] += 1
                return


def _classify(result) -> str:
    """
    What actually happened to one scanned message.

    A fail-closed block is a BLOCK with SYSTEM_ERROR as its reason: the detector
    did not decide anything, the request was refused because it could not be
    inspected. It reaches the caller looking exactly like a content block, which
    is why counting only transport errors reports a run where every message was
    refused as a run with no errors at all.
    """
    decision = result.decision.decision.value
    reason   = getattr(result.decision, "primary_reason", None)

    if decision == "BLOCK":
        return "blocked_by_failure" if reason == "SYSTEM_ERROR" else "blocked_by_content"
    return "served"


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
) -> tuple[float, float, float, float, float, int, collections.Counter]:
    """
    One Scan-All request: scan N messages, then append N audit rows in order.

    Returns (total_ms, scan_ms, audit_ms, lock_wait_ms, lock_hold_ms, errors,
    outcomes), where outcomes counts what happened to each scanned MESSAGE:
    served, blocked_by_content, or blocked_by_failure.
    Audit rows are written sequentially on purpose -- that is what the proxy
    does, because the chain cannot be built from concurrent writers.

    The two lock figures are the ones the maximum has to be chosen on, and a
    mean latency hides both. The chain takes a per-tenant advisory lock that is
    held until commit, so:

      lock_wait_ms  how long this request sat behind other requests from the
                    same tenant before it could start writing -- head-of-line
                    blocking, which is what a caller experiences as a stall
                    caused by somebody else's long conversation.
      lock_hold_ms  how long this request kept every other request in the
                    tenant out. This is the figure that scales with N, and one
                    request's hold is every other request's wait.

    The lock is taken explicitly first so acquisition can be timed on its own.
    It is the same lock the repository takes, and advisory locks re-enter freely
    within a transaction, so the writes below add no further waiting.
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
        return (0.0, 0.0, 0.0, 0.0, 0.0, n_messages,
                collections.Counter({"transport_error": n_messages}))
    scan_ms = (time.monotonic() - scan_started) * 1000

    outcomes: collections.Counter[str] = collections.Counter(
        _classify(result) for _incoming, result in scanned
    )

    audit_started = time.monotonic()
    lock_wait_ms  = 0.0
    lock_hold_ms  = 0.0
    async with session_factory() as session:
        lock_requested = time.monotonic()
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:tid))"), {"tid": tenant_id},
        )
        lock_acquired = time.monotonic()
        lock_wait_ms  = (lock_acquired - lock_requested) * 1000

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

        # Commit rather than letting the block roll back. The lock is held until
        # the transaction ends either way, but only a commit pays the write cost
        # a real request pays, and that cost is inside the hold.
        try:
            await session.commit()
        except Exception:
            errors += 1
        lock_hold_ms = (time.monotonic() - lock_acquired) * 1000

    audit_ms = (time.monotonic() - audit_started) * 1000

    return (
        (time.monotonic() - started) * 1000,
        scan_ms, audit_ms, lock_wait_ms, lock_hold_ms, errors, outcomes,
    )


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
    waits:  list[float] = []
    holds:  list[float] = []
    errors = 0
    outcomes: collections.Counter[str] = collections.Counter()

    semaphore = asyncio.Semaphore(concurrency)

    async def worker(index: int):
        nonlocal errors
        async with semaphore:
            total_ms, scan_ms, audit_ms, wait_ms, hold_ms, failed, counts = await _one_request(
                session_factory, tenant_id, n_messages,
                trace_seed=f"req_{uuid.uuid4().hex}",
            )
            totals.append(total_ms)
            scans.append(scan_ms)
            audits.append(audit_ms)
            waits.append(wait_ms)
            holds.append(hold_ms)
            errors += failed
            outcomes.update(counts)

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
        # One request's hold is every other request's wait, so the worst hold is
        # the ceiling on what a queued caller can be made to wait for each
        # request ahead of it. The worst wait is what somebody actually waited.
        "lock_wait_mean": statistics.fmean(waits) if waits else 0.0,
        "lock_wait_max":  max(waits) if waits else 0.0,
        "lock_hold_mean": statistics.fmean(holds) if holds else 0.0,
        "lock_hold_max":  max(holds) if holds else 0.0,
        "throughput":   scanned_messages / wall if wall else 0.0,
        "errors":       errors,
        # What happened to each scanned message, so a run in which everything
        # was refused cannot report itself as a run with no errors.
        "served":             outcomes["served"],
        "blocked_by_content": outcomes["blocked_by_content"],
        "blocked_by_failure": outcomes["blocked_by_failure"],
        "transport_error":    outcomes["transport_error"],
        "failure_block_rate": (
            outcomes["blocked_by_failure"] / scanned_messages if scanned_messages else 0.0
        ),
    }


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--messages",    default="1,5,10,20,50")
    parser.add_argument("--concurrency", default="1,4,8")
    parser.add_argument("--requests",    type=int, default=10)
    parser.add_argument(
        "--no-transformer", action="store_true",
        help="measure the default build, where Tier 2 is not installed",
    )
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

    timeouts = _TimeoutCounter()
    logging.getLogger("wrapsec").addHandler(timeouts)
    logging.getLogger("wrapsec").setLevel(logging.WARNING)

    from engine.detection.transformer_detector import TransformerDetector
    tier2 = "off (default build)" if not TransformerDetector._class_ready else "ON (optional build)"

    print(f"\nScan-All cost, single tenant, {args.requests} requests per point")
    print(f"Tier-2 transformer: {tier2}\n")
    print(f"{'msgs':>5} {'conc':>5} {'p50 ms':>9} {'p95 ms':>9} {'p99 ms':>9} "
          f"{'scan ms':>9} {'audit ms':>9} {'ms/row':>8} "
          f"{'wait avg':>9} {'wait max':>9} {'hold avg':>9} {'hold max':>9} "
          f"{'msg/s':>8} {'served':>7} {'blk:cnt':>8} {'blk:FAIL':>9} {'err':>5}")
    print("-" * 160)

    rows: list[dict] = []
    try:
        for n in message_counts:
            for c in concurrencies:
                row = await _measure(factory, tenant_id, n, c, args.requests)
                rows.append(row)
                print(f"{row['messages']:>5} {row['concurrency']:>5} "
                      f"{row['p50']:>9.1f} {row['p95']:>9.1f} {row['p99']:>9.1f} "
                      f"{row['scan_mean']:>9.1f} {row['audit_mean']:>9.1f} "
                      f"{row['audit_per_row']:>8.1f} "
                      f"{row['lock_wait_mean']:>9.1f} {row['lock_wait_max']:>9.1f} "
                      f"{row['lock_hold_mean']:>9.1f} {row['lock_hold_max']:>9.1f} "
                      f"{row['throughput']:>8.1f} "
                      f"{row['served']:>7} {row['blocked_by_content']:>8} "
                      f"{row['blocked_by_failure']:>9} {row['errors']:>5}")
    finally:
        await engine.dispose()

    scanned = sum(r["served"] + r["blocked_by_content"] + r["blocked_by_failure"]
                  for r in rows)
    failed  = sum(r["blocked_by_failure"] for r in rows)
    rate    = (failed / scanned) if scanned else 0.0

    print("\nRead the two lock columns first. `hold` is how long one request keeps every\n"
          "other request in the tenant out, and it is what grows with the message count.\n"
          "`wait` is what a request spent queued behind the ones ahead of it, and it is\n"
          "what a caller experiences as a stall somebody else caused. At concurrency 1\n"
          "there is nothing to wait for, so a non-trivial wait there means contention\n"
          "from outside this run.\n\n"
          "The maximum message count is a bound on hold time. Raising it raises what one\n"
          "tenant can do to its own other requests.\n")

    print("Outcome of every scanned message")
    print(f"  served                    {scanned - failed - sum(r['blocked_by_content'] for r in rows):>7}")
    print(f"  blocked on content        {sum(r['blocked_by_content'] for r in rows):>7}")
    print(f"  blocked by DETECTOR FAILURE {failed:>5}   <- {rate:.1%} of all scanned messages")
    print(f"  transport errors          {sum(r['transport_error'] for r in rows):>7}")

    if timeouts.counts:
        print("\nDetector timeouts, by source")
        for source, count in timeouts.counts.most_common():
            print(f"  {source:<16} {count:>7}")

    print("\nThe failure-block line is the one to act on. Those requests were refused\n"
          "because a detector ran out of time, not because anything was found in them,\n"
          "and the caller cannot tell the two apart -- both arrive as a BLOCK. A run\n"
          "with a high rate here is legitimate traffic being turned away under load,\n"
          "which counting transport errors alone would report as a clean run.\n")

    # The run commits, so it leaves rows behind. Chain rows are append-only by
    # trigger, but a synthetic tenant should not linger in a real database.
    print(f"Rows were committed under tenant_id={tenant_id}. To remove them:\n"
          f"  DELETE FROM audit_logs WHERE tenant_id = '{tenant_id}';\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
