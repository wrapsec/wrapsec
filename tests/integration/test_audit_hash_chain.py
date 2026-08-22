# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for the hash-chained audit writer.

These exercise db/repositories/audit.py against a real (SQLite) session:
the chain-under-lock logic in AuditRepository.create() is what enforces
chain integrity, and unit tests over the pure hash module cannot prove
that the write path stitches rows together correctly.
"""
from __future__ import annotations

import itertools
from datetime import datetime, timezone

import pytest

from db.models import AuditLogModel
from db.repositories.audit import AuditRepository
from security.audit_chain import compute_record_hash


def _row(trace_id: str, tenant_id: str | None, offset_sec: int = 0) -> dict:
    """Minimal valid audit_logs payload with a stable created_at."""
    return {
        "trace_id":       trace_id,
        "decision":       "ALLOW",
        "risk_score":     0.1,
        "threats":        [],
        "input_hash":     "sha256:test",
        "detection_mode": "fast",
        "execution_mode": "scan_only",
        "llm_invoked":    False,
        "latency_ms":     1.0,
        "tenant_id":      tenant_id,
        "created_at":     datetime(2026, 7, 27, 10, 0, offset_sec, tzinfo=timezone.utc),
    }


class TestChainSingleTenant:

    @pytest.mark.asyncio
    async def test_genesis_row_has_null_prev_hash(self, test_db):
        repo = AuditRepository(test_db)
        row  = await repo.create(_row("t_genesis", tenant_id="tenant_a"))

        assert row.prev_hash   is None
        assert row.record_hash is not None
        assert len(row.record_hash) == 64
        # Genesis hash matches the pure-function output (prev_hash="").
        expected = compute_record_hash(
            {**_row("t_genesis", tenant_id="tenant_a"), "prev_hash": None,
             "record_hash": None},
            prev_hash=None,
        )
        assert row.record_hash == expected

    @pytest.mark.asyncio
    async def test_second_row_links_to_first(self, test_db):
        repo = AuditRepository(test_db)
        row1 = await repo.create(_row("t1", tenant_id="tenant_a", offset_sec=0))
        row2 = await repo.create(_row("t2", tenant_id="tenant_a", offset_sec=1))

        assert row2.prev_hash == row1.record_hash
        # Row2 hash is genuinely dependent on row1 (would differ if row1
        # were tampered with).
        assert row2.record_hash != row1.record_hash

    @pytest.mark.asyncio
    async def test_three_row_chain_is_verifiable(self, test_db):
        repo = AuditRepository(test_db)
        rows = []
        for i in range(3):
            rows.append(
                await repo.create(_row(f"tt_{i}", tenant_id="tenant_a", offset_sec=i))
            )

        assert rows[0].prev_hash is None
        assert rows[1].prev_hash == rows[0].record_hash
        assert rows[2].prev_hash == rows[1].record_hash


class TestChainMultiTenant:

    @pytest.mark.asyncio
    async def test_two_tenants_have_independent_chains(self, test_db):
        repo = AuditRepository(test_db)
        a1 = await repo.create(_row("a1", tenant_id="tenant_a", offset_sec=0))
        b1 = await repo.create(_row("b1", tenant_id="tenant_b", offset_sec=1))
        a2 = await repo.create(_row("a2", tenant_id="tenant_a", offset_sec=2))
        b2 = await repo.create(_row("b2", tenant_id="tenant_b", offset_sec=3))

        # Genesis for each tenant.
        assert a1.prev_hash is None
        assert b1.prev_hash is None
        # Tenant A's second row links back to A's first, NOT to B's
        # -- otherwise cross-tenant scan volume leaks into the chain
        # and a per-tenant verifier gets bogus results.
        assert a2.prev_hash == a1.record_hash
        assert b2.prev_hash == b1.record_hash
        assert a2.prev_hash != b1.record_hash


class TestNoTenant:

    @pytest.mark.asyncio
    async def test_row_without_tenant_id_is_unchained(self, test_db):
        repo = AuditRepository(test_db)
        row  = await repo.create(_row("no_tenant", tenant_id=None))

        assert row.prev_hash   is None
        assert row.record_hash is None

    @pytest.mark.asyncio
    async def test_unchained_rows_do_not_pollute_tenant_chain(self, test_db):
        # A subsequent tenanted write must ignore any interleaved
        # untenanted rows -- otherwise "unattributed" rows would
        # silently join a random tenant's chain.
        repo = AuditRepository(test_db)
        await repo.create(_row("no_tid",   tenant_id=None))
        row1 = await repo.create(_row("t1", tenant_id="tenant_a"))
        await repo.create(_row("no_tid2",  tenant_id=None))
        row2 = await repo.create(_row("t2", tenant_id="tenant_a"))

        assert row1.prev_hash is None
        assert row2.prev_hash == row1.record_hash


class TestPreV1_2LegacyRows:

    @pytest.mark.asyncio
    async def test_legacy_null_hash_rows_do_not_break_new_chain(self, test_db):
        # Simulate a v1.0.x row that predates the hash chain by inserting
        # directly via the ORM (bypassing AuditRepository.create()).
        legacy = AuditLogModel(
            trace_id       = "legacy_row",
            decision       = "ALLOW",
            risk_score     = 0.0,
            threats        = [],
            input_hash     = "sha256:legacy",
            detection_mode = "fast",
            execution_mode = "scan_only",
            llm_invoked    = False,
            latency_ms     = 0.5,
            tenant_id      = "tenant_a",
            created_at     = datetime(2026, 7, 20, 8, 0, 0, tzinfo=timezone.utc),
        )
        test_db.add(legacy)
        await test_db.commit()

        repo = AuditRepository(test_db)
        first_v1_2 = await repo.create(
            _row("first_after_upgrade", tenant_id="tenant_a", offset_sec=1)
        )
        # The first v1.2 row for this tenant must be genesis, NOT chained
        # off a NULL record_hash (which would corrupt every downstream hash).
        assert first_v1_2.prev_hash is None
        assert first_v1_2.record_hash is not None


class TestBatchAtomicity:
    """
    A per-message audit set is written all-or-nothing.

    Scan-All turns one request into N rows. Written one at a time they commit as
    they go, so a failure partway through leaves the earlier rows persisted: an
    audit set silently shorter than the request it describes, with no gap marker
    and nothing distinguishing it from a request that scanned fewer messages. A
    partial record that reads as complete is worse than a recorded failure.
    """

    @pytest.mark.asyncio
    async def test_a_whole_batch_commits_and_chains(self, test_db):
        from sqlalchemy import select

        repo   = AuditRepository(test_db)
        tenant = "11111111-1111-1111-1111-111111111111"

        await repo.create_many([_row(f"batch-{i}", tenant, offset_sec=i) for i in range(5)])

        rows = (await test_db.execute(
            select(AuditLogModel)
            .where(AuditLogModel.tenant_id == tenant)
            .order_by(AuditLogModel.created_at)
        )).scalars().all()

        assert len(rows) == 5
        # Each row hashes the one before it, first row opens the chain.
        assert rows[0].prev_hash is None
        for earlier, later in itertools.pairwise(rows):
            assert later.prev_hash == earlier.record_hash, (
                "the batch did not stitch its rows together"
            )

    @pytest.mark.asyncio
    async def test_a_failure_partway_leaves_nothing_behind(self, test_db):
        """
        The regression this exists for: rows 1-4 durably committed while row 5
        failed, and the caller none the wiser.
        """
        from sqlalchemy import select

        repo   = AuditRepository(test_db)
        tenant = "22222222-2222-2222-2222-222222222222"

        rows = [_row(f"partial-{i}", tenant, offset_sec=i) for i in range(5)]
        rows[3]["no_such_column"] = "boom"      # fails after rows 0-2 are staged

        with pytest.raises(TypeError):
            await repo.create_many(rows)

        survivors = (await test_db.execute(
            select(AuditLogModel).where(AuditLogModel.tenant_id == tenant)
        )).scalars().all()

        assert survivors == [], (
            f"{len(survivors)} row(s) survived a failed batch; a short audit set "
            f"is not evidence"
        )

    @pytest.mark.asyncio
    async def test_a_failed_batch_does_not_break_the_chain_for_later_writes(self, test_db):
        """
        A rolled-back batch must leave the tenant's chain exactly where it was,
        so the next write still links to the last good row.
        """
        from sqlalchemy import select

        repo   = AuditRepository(test_db)
        tenant = "33333333-3333-3333-3333-333333333333"

        good = await repo.create_many([_row("chain-a", tenant, offset_sec=0)])
        anchor_hash = good[0].record_hash

        doomed = [_row("chain-x", tenant, offset_sec=1)]
        doomed[0]["no_such_column"] = "boom"
        with pytest.raises(TypeError):
            await repo.create_many(doomed)

        await repo.create_many([_row("chain-b", tenant, offset_sec=2)])

        rows = (await test_db.execute(
            select(AuditLogModel)
            .where(AuditLogModel.tenant_id == tenant)
            .order_by(AuditLogModel.created_at)
        )).scalars().all()

        assert [r.trace_id for r in rows] == ["chain-a", "chain-b"]
        assert rows[1].prev_hash == anchor_hash, (
            "the write after a failed batch did not link to the last good row"
        )

    @pytest.mark.asyncio
    async def test_a_mixed_tenant_batch_is_refused(self, test_db):
        """
        The lock and the chain are both per tenant, so a mixed batch has no one
        correct ordering. Refuse it rather than pick one.
        """
        repo = AuditRepository(test_db)
        with pytest.raises(ValueError, match="one tenant"):
            await repo.create_many([
                _row("mixed-a", "44444444-4444-4444-4444-444444444444"),
                _row("mixed-b", "55555555-5555-5555-5555-555555555555"),
            ])

    @pytest.mark.asyncio
    async def test_an_empty_batch_is_a_no_op(self, test_db):
        repo = AuditRepository(test_db)
        assert await repo.create_many([]) == []
