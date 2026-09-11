# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The verifier must tell three different things apart.

A chain reader that reports everything unusual as tampering is worse than no
reader: retention deletes rows on purpose, so such a tool cries wolf on every
schedule and an operator learns to ignore it. These pin the distinctions.

  * GAP   -- rows deleted from the middle. Legitimate; the immutability trigger
             covers UPDATE only, so DELETE is by design.
  * BREAK -- content changed, or a link that does not hold between two rows that
             are both present.
  * FORK  -- two rows claiming the same predecessor: the signature of the defect
             this workstream fixed. Reported, never repaired.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, text

from db.models import AuditLogModel, TenantModel
from db.repositories.audit import AuditRepository
from scripts.verify_audit_chain import verify_tenant
from services.time import utc_now

pytestmark = pytest.mark.pg


def _row(tenant_id) -> dict:
    return {
        "trace_id":       f"req_{uuid.uuid4().hex}",
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


async def _seed(db, count: int):
    tid = uuid.uuid4()
    db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await db.commit()
    for _ in range(count):
        await AuditRepository(db).create(_row(tid))
    return tid


@pytest.mark.asyncio
async def test_a_healthy_chain_verifies(pg_db):
    tid = await _seed(pg_db, 5)

    report = await verify_tenant(pg_db, str(tid))

    assert report.ok
    assert report.rows_verified == 5
    assert report.first_break is None
    assert report.forks == []
    assert report.gap_spans == []
    assert report.format_counts == {2: 5}


@pytest.mark.asyncio
async def test_a_retention_style_deletion_is_a_gap_not_tampering(pg_db):
    """The case that decides whether the tool is usable. Deleting interior rows
    is what retention does; calling it tampering would make every scheduled
    cleanup look like an attack."""
    tid = await _seed(pg_db, 6)

    await pg_db.execute(
        delete(AuditLogModel).where(
            AuditLogModel.tenant_id == str(tid),
            AuditLogModel.chain_seq.in_([3, 4]),
        )
    )
    await pg_db.commit()

    report = await verify_tenant(pg_db, str(tid))

    assert report.ok, (
        f"a retention deletion was reported as a problem: break={report.first_break} "
        f"forks={report.forks}"
    )
    assert report.gap_spans, "the deletion left no recorded gap"
    assert report.first_break is None


@pytest.mark.asyncio
async def test_modified_content_is_reported_as_a_break(pg_db):
    """The trigger blocks UPDATE on chained rows, so tampering is simulated the
    way a database superuser would do it -- by disabling the trigger for the
    session. That is the threat model: someone with direct database access."""
    tid = await _seed(pg_db, 4)

    await pg_db.execute(text("SET session_replication_role = replica"))
    await pg_db.execute(
        AuditLogModel.__table__.update()
        .where(AuditLogModel.tenant_id == str(tid), AuditLogModel.chain_seq == 3)
        .values(decision="BLOCK")
    )
    await pg_db.execute(text("SET session_replication_role = DEFAULT"))
    await pg_db.commit()

    report = await verify_tenant(pg_db, str(tid))

    assert not report.ok
    assert report.first_break is not None
    assert report.first_break["chain_seq"] == 3
    assert report.first_break["kind"] == "content_modified"


@pytest.mark.asyncio
async def test_a_fork_is_reported_and_not_repaired(pg_db):
    """The SA-02 signature. A fork found today is almost certainly history --
    written by the pre-fix writer -- so the verifier names it and leaves it
    alone. Repairing it would destroy the evidence of what happened."""
    tid = await _seed(pg_db, 3)

    rows = (await pg_db.execute(
        AuditLogModel.__table__.select()
        .where(AuditLogModel.tenant_id == str(tid))
        .order_by(AuditLogModel.chain_seq)
    )).all()
    shared_prev = rows[1].prev_hash

    await pg_db.execute(text("SET session_replication_role = replica"))
    await pg_db.execute(
        AuditLogModel.__table__.update()
        .where(AuditLogModel.tenant_id == str(tid), AuditLogModel.chain_seq == 3)
        .values(prev_hash=shared_prev)
    )
    await pg_db.execute(text("SET session_replication_role = DEFAULT"))
    await pg_db.commit()

    report = await verify_tenant(pg_db, str(tid))

    assert not report.ok
    assert report.forks, "two rows share a prev_hash and no fork was reported"
    assert 3 in report.forks[0]["chain_seqs"]

    # untouched: the verifier reads, it does not write
    after = (await pg_db.execute(
        AuditLogModel.__table__.select()
        .where(AuditLogModel.tenant_id == str(tid), AuditLogModel.chain_seq == 3)
    )).first()
    assert after.prev_hash == shared_prev, "the verifier modified the chain"


@pytest.mark.asyncio
async def test_unchained_rows_are_counted_not_treated_as_breaks(pg_db):
    """Rows written before the chain existed carry no hash. They belong to no
    chain, and reporting them as breaks would flag every pre-v1.2 deployment."""
    tid = await _seed(pg_db, 2)

    legacy = _row(tid)
    legacy.update({"prev_hash": None, "record_hash": None, "chain_seq": None,
                   "created_at": utc_now()})
    pg_db.add(AuditLogModel(**legacy))
    await pg_db.commit()

    report = await verify_tenant(pg_db, str(tid))

    assert report.ok
    assert report.unchained_rows == 1
    assert report.rows_verified == 2
