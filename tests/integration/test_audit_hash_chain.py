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

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

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
        "created_at":     datetime(2026, 7, 27, 10, 0, offset_sec),
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
            created_at     = datetime(2026, 7, 20, 8, 0, 0),
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
