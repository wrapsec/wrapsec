#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Walk a tenant's audit hash chain and report what it finds.

The chain has been written since v1.2 and nothing has ever read it back. A hash
chain nobody verifies is not tamper-evident: it is tamper-RECORDING, which is a
different and much weaker claim. This is the reader.

    python scripts/verify_audit_chain.py                 # every tenant
    python scripts/verify_audit_chain.py --tenant <uuid> # one
    python scripts/verify_audit_chain.py --json          # machine-readable

AN OPERATOR TOOL, NOT AN ENDPOINT. It reads whole chains, which is the opposite
shape from anything the published API serves, and the published surface is a
frozen 28-operation contract. It belongs with the migration tooling.

WHAT IT DISTINGUISHES, and why the distinction is the whole design:

  * BREAK  -- a row whose stored hash does not match a recomputation of its own
    content, or a seq-adjacent pair whose link does not hold. Someone changed
    something.
  * FORK   -- two rows sharing a prev_hash. This is the shape the pre-0025
    writer produced when two timestamps arrived out of insertion order. It is
    reported separately because a fork found today is almost certainly HISTORY,
    not an attack, and it is not repaired: rewriting it would destroy the
    evidence of what actually happened.
  * GAP    -- a jump in chain_seq whose successor links to a row that is no
    longer present. This is what RETENTION looks like. Deleting old rows is
    legitimate and unrestricted (the immutability trigger covers UPDATE only),
    so a verifier that called this tampering would be wrong every time
    retention ran, and would train an operator to ignore it.

WHAT IT CANNOT DETECT. Deleting the most recent rows leaves a shorter chain that
is internally perfect. Nothing in the database can distinguish that from a
tenant that simply stopped writing. Detecting it needs an anchor published
outside this database, which does not exist in this tree. The report says so
rather than implying coverage.

EXIT CODE: 0 when every chain verifies, including one with retention gaps.
Non-zero when any break or fork is found.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("TESTING", "false")


@dataclass
class TenantReport:
    tenant_id:      str
    rows_verified:  int = 0
    format_counts:  dict[int, int] = field(default_factory=dict)
    genesis_seq:    int | None = None
    tip_seq:        int | None = None
    gap_spans:      list[tuple[int, int]] = field(default_factory=list)
    forks:          list[dict] = field(default_factory=list)
    first_break:    dict | None = None
    unchained_rows: int = 0

    @property
    def ok(self) -> bool:
        """Gaps alone are a clean chain. Breaks and forks are not."""
        return self.first_break is None and not self.forks


def _row_dict(row) -> dict:
    """The row as the writer saw it, so the recomputation uses the same input."""
    return {c.name: getattr(row, c.name) for c in row.__table__.columns}


async def verify_tenant(session, tenant_id) -> TenantReport:
    from sqlalchemy import select

    from db.models import AuditLogModel
    from security.audit_chain import compute_record_hash

    report = TenantReport(tenant_id=str(tenant_id))

    rows = (
        await session.execute(
            select(AuditLogModel)
            .where(AuditLogModel.tenant_id == tenant_id)
            .order_by(AuditLogModel.chain_seq.asc())
        )
    ).scalars().all()

    chained = [r for r in rows if r.record_hash is not None]
    report.unchained_rows = len(rows) - len(chained)
    if not chained:
        return report

    report.genesis_seq = chained[0].chain_seq
    report.tip_seq     = chained[-1].chain_seq

    # A fork is two rows claiming the same predecessor. Detected across the whole
    # chain rather than pairwise, because the two halves of a fork need not be
    # adjacent once later rows have been appended to one of them.
    by_prev: dict[str, list] = {}
    for row in chained:
        if row.prev_hash is not None:
            by_prev.setdefault(row.prev_hash, []).append(row)
    for prev, sharing in by_prev.items():
        if len(sharing) > 1:
            report.forks.append({
                "shared_prev_hash": prev,
                "chain_seqs":       [r.chain_seq for r in sharing],
                "trace_ids":        [r.trace_id for r in sharing],
            })

    previous = None
    for row in chained:
        fmt = row.chain_format
        report.format_counts[fmt] = report.format_counts.get(fmt, 0) + 1

        # 1. content: does the row still hash to what it stored?
        try:
            recomputed = compute_record_hash(_row_dict(row), row.prev_hash, fmt)
        except ValueError as unknown_format:
            report.first_break = report.first_break or {
                "chain_seq": row.chain_seq,
                "kind":      "unknown_format",
                "detail":    str(unknown_format),
            }
            break
        if recomputed != row.record_hash:
            report.first_break = report.first_break or {
                "chain_seq": row.chain_seq,
                "trace_id":  row.trace_id,
                "kind":      "content_modified",
                "detail":    "the row does not hash to its stored record_hash",
            }
            break

        # 2. linkage, but only where both ends are PRESENT. A successor whose
        #    predecessor was deleted is a gap, not a break.
        if previous is not None:
            contiguous = (row.chain_seq or 0) == (previous.chain_seq or 0) + 1
            if contiguous:
                if row.prev_hash != previous.record_hash:
                    report.first_break = report.first_break or {
                        "chain_seq": row.chain_seq,
                        "trace_id":  row.trace_id,
                        "kind":      "link_broken",
                        "detail":    "prev_hash does not match the preceding row",
                    }
                    break
            else:
                report.gap_spans.append((previous.chain_seq, row.chain_seq))

        report.rows_verified += 1
        previous = row

    return report


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", help="verify one tenant id")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    from sqlalchemy import select

    from db.models import AuditLogModel
    from db.session import AsyncSessionFactory

    reports: list[TenantReport] = []
    async with AsyncSessionFactory() as session:
        if args.tenant:
            tenants = [args.tenant]
        else:
            tenants = [
                t for (t,) in (
                    await session.execute(
                        select(AuditLogModel.tenant_id)
                        .where(AuditLogModel.tenant_id.is_not(None))
                        .distinct()
                    )
                ).all()
            ]
        for tenant in tenants:
            reports.append(await verify_tenant(session, tenant))

    if args.json:
        print(json.dumps(
            {
                "tenants": [asdict(r) for r in reports],
                "tail_deletion": "undetectable without external anchoring",
            },
            indent=2, default=str,
        ))
    else:
        for r in reports:
            status = "OK" if r.ok else "PROBLEM"
            print(f"[{status}] tenant {r.tenant_id}")
            print(f"    rows verified : {r.rows_verified}")
            print(f"    formats       : {r.format_counts}")
            print(f"    seq range     : {r.genesis_seq} -> {r.tip_seq}")
            if r.unchained_rows:
                print(f"    unchained     : {r.unchained_rows} (pre-chain rows, not in any chain)")
            if r.gap_spans:
                print(f"    gaps          : {r.gap_spans}  (retention; not tampering)")
            for fork in r.forks:
                print(f"    FORK          : seqs {fork['chain_seqs']} share a prev_hash")
            if r.first_break:
                print(f"    BREAK         : {r.first_break}")
        print("\nNote: deletion of the most recent rows cannot be detected here. "
              "It leaves a shorter chain that is internally consistent, and this "
              "tool has no anchor outside the database to compare a tip against.")

    return 0 if all(r.ok for r in reports) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
