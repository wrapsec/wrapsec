# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The chain is ordered by sequence, so a clock cannot fork it.

The predecessor used to be selected with `ORDER BY created_at DESC`, and
`created_at` is stamped BEFORE the advisory lock that serialises the write. Two
rows whose timestamps were not in insertion order -- a clock stepping back, or
two requests that both stamped the time before either took the lock -- selected
the SAME predecessor and both stored its hash as their `prev_hash`. That is a
fork, and it orphans a row from the chain.

These run on real PostgreSQL because that is where the defect lives: the SQLite
suites are single-writer per database, so they cannot produce two concurrent
writers contending for one tenant's lock, and they cannot exercise
`pg_advisory_xact_lock` at all.
"""

from __future__ import annotations

import asyncio
import uuid
from itertools import pairwise

import pytest

from db.models import AuditLogModel, TenantModel
from db.repositories.audit import AuditRepository
from db.session import AsyncSessionFactory
from services.time import utc_now

pytestmark = pytest.mark.pg


def _row(tenant_id, *, created_at=None, trace=None) -> dict:
    """A minimal audit row. Only the chain columns matter here."""
    data = {
        "trace_id":       trace or f"req_{uuid.uuid4().hex}",
        "tenant_id":      str(tenant_id),
        "decision":       "ALLOW",
        "risk_score":     0.0,
        "threats":        [],
        "input_hash":     uuid.uuid4().hex,
        "detection_mode": "fast",
        "execution_mode": "scan_only",
        "llm_invoked":    False,
        "latency_ms":     1.0,
        "input_length":   10,
        "primary_reason": "NO_THREAT_DETECTED",
    }
    if created_at is not None:
        data["created_at"] = created_at
    return data


async def _tenant(db) -> uuid.UUID:
    tid = uuid.uuid4()
    db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await db.commit()
    return tid


async def _chain(db, tenant_id) -> list[AuditLogModel]:
    from sqlalchemy import select

    return list((await db.execute(
        select(AuditLogModel)
        .where(AuditLogModel.tenant_id == str(tenant_id))
        .order_by(AuditLogModel.chain_seq.asc())
    )).scalars().all())


@pytest.mark.asyncio
async def test_a_clock_regression_no_longer_forks_the_chain(pg_db):
    """The exact reported reproduction: write at t=5, then t=3, then t=6.

    Under `ORDER BY created_at DESC` the second write saw the t=5 row, and the
    THIRD write also saw the t=5 row -- because t=3 had gone in behind it. Both
    stored the same prev_hash. Ordered by sequence, insertion order is what the
    chain follows and the timestamps are irrelevant to it.
    """
    tid  = await _tenant(pg_db)
    base = utc_now()

    from datetime import timedelta
    for offset in (5, 3, 6):
        await AuditRepository(pg_db).create(
            _row(tid, created_at=base + timedelta(seconds=offset))
        )

    rows = await _chain(pg_db, tid)
    assert len(rows) == 3

    assert [r.chain_seq for r in rows] == [1, 2, 3], (
        f"positions are not insertion order: {[r.chain_seq for r in rows]}"
    )
    prevs = [r.prev_hash for r in rows]
    assert prevs[0] is None, "the first row is genesis and must have no predecessor"
    assert prevs[1] == rows[0].record_hash
    assert prevs[2] == rows[1].record_hash
    assert len({p for p in prevs if p}) == 2, (
        f"two rows share a prev_hash -- the chain forked: {prevs}"
    )


@pytest.mark.asyncio
async def test_concurrent_writers_produce_one_linear_chain(pg_url):
    """Real concurrency against real PostgreSQL.

    Each writer gets its OWN session and commits independently, so they contend
    for the tenant's advisory lock exactly as separate requests do. The
    assertion is structural rather than about any one row: N writes must produce
    a chain of N links with every position used once and every link resolving to
    its predecessor.
    """
    async with AsyncSessionFactory() as setup:
        tid = await _tenant(setup)

    writers = 12

    async def _write(_i):
        async with AsyncSessionFactory() as session:
            await AuditRepository(session).create(_row(tid))

    await asyncio.gather(*(_write(i) for i in range(writers)))

    async with AsyncSessionFactory() as check:
        rows = await _chain(check, tid)

    assert len(rows) == writers

    seqs = [r.chain_seq for r in rows]
    assert seqs == list(range(1, writers + 1)), (
        f"positions are not a dense 1..N run: {seqs}. Two writers took the same "
        "position, so the lock is not serialising allocation."
    )

    prevs = [r.prev_hash for r in rows]
    assert prevs[0] is None
    assert len(set(prevs[1:])) == writers - 1, (
        "two rows share a prev_hash -- concurrent writers forked the chain"
    )
    for earlier, later in pairwise(rows):
        assert later.prev_hash == earlier.record_hash, (
            f"link broken between positions {earlier.chain_seq} and {later.chain_seq}"
        )


@pytest.mark.asyncio
async def test_new_rows_are_written_in_format_two_and_hash_their_position(pg_db):
    """`chain_seq` must be INSIDE the hash, or renumbering rows leaves every
    hash valid and the sequence documents an order it does not attest to."""
    from security.audit_chain import CURRENT_CHAIN_FORMAT, compute_record_hash

    tid = await _tenant(pg_db)
    await AuditRepository(pg_db).create(_row(tid))
    row = (await _chain(pg_db, tid))[0]

    assert row.chain_format == CURRENT_CHAIN_FORMAT == 2

    as_written = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    assert compute_record_hash(as_written, row.prev_hash, 2) == row.record_hash

    moved = dict(as_written, chain_seq=(row.chain_seq or 0) + 10)
    assert compute_record_hash(moved, row.prev_hash, 2) != row.record_hash, (
        "changing chain_seq did not change the hash: the position is outside "
        "the hashed content and can be rewritten freely"
    )


@pytest.mark.asyncio
async def test_a_batch_write_keeps_positions_dense_and_linked(pg_db):
    """`create_many` chains in memory under one lock; the positions it assigns
    must continue the tenant's sequence rather than restart it."""
    tid = await _tenant(pg_db)

    await AuditRepository(pg_db).create(_row(tid))
    await AuditRepository(pg_db).create_many([_row(tid) for _ in range(4)])

    rows = await _chain(pg_db, tid)

    assert [r.chain_seq for r in rows] == [1, 2, 3, 4, 5]
    for earlier, later in pairwise(rows):
        assert later.prev_hash == earlier.record_hash


@pytest.mark.asyncio
async def test_a_stored_row_can_be_re_verified_from_storage(pg_db):
    """The property a verifier depends on, and the one that was broken.

    The writer hashes its own dict; the verifier recomputes from the row on
    disk. Those inputs must be identical. They were not: canonical fields the
    writer omitted carried column defaults on disk -- `attribution_verified` and
    `principal_type` from Python defaults, `input_source` from a SERVER default
    -- so the stored row hashed to something else and could never be verified.

    Invisible for as long as nothing read the chain back. It surfaced on the
    verifier's first run against a real row.
    """
    from security.audit_chain import compute_record_hash

    tid = await _tenant(pg_db)
    await AuditRepository(pg_db).create(_row(tid))
    row = (await _chain(pg_db, tid))[0]

    as_stored = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    assert compute_record_hash(as_stored, row.prev_hash, row.chain_format) == row.record_hash, (
        "a freshly written row does not hash to its own stored record_hash, so "
        "no verifier can ever confirm it"
    )
