# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Repository unit test for AuditRepository.get_stats_by_source (Security by Source).

Runs against SQLite via the shared test_db fixture, so it exercises the Python
threat-aggregation fallback (the non-PostgreSQL branch). The PostgreSQL jsonb
path is covered by tests/integration/test_api_by_source.py.
"""

import uuid

import pytest

from db.models import AuditLogModel
from db.repositories.audit import AuditRepository

TENANT = str(uuid.uuid4())


def _row(input_source, decision, risk, threats):
    return AuditLogModel(
        id             = uuid.uuid4(),
        trace_id       = "req_" + uuid.uuid4().hex[:12],
        decision       = decision,
        risk_score     = risk,
        threats        = threats,
        input_hash     = "sha256:" + uuid.uuid4().hex,
        detection_mode = "fast",
        execution_mode = "scan_only",
        llm_invoked    = False,
        latency_ms     = 5.0,
        tenant_id      = TENANT,
        source         = "api",
        input_source   = input_source,
    )


async def _seed(db):
    db.add_all([
        _row("user_prompt",        "ALLOW",    0.0, []),
        _row("user_prompt",        "ALLOW",    0.1, []),
        _row("retrieved_document", "BLOCK",    0.95, ["PROMPT_INJECTION"]),
        _row("retrieved_document", "BLOCK",    0.90, ["PROMPT_INJECTION", "JAILBREAK"]),
        _row("retrieved_document", "SANITIZE", 0.50, []),
        _row("tool_output",        "ALLOW",    0.2, []),
    ])
    await db.commit()


@pytest.mark.asyncio
async def test_by_source_aggregates_and_threats(test_db):
    await _seed(test_db)
    repo = AuditRepository(test_db)
    rows = await repo.get_stats_by_source(tenant_id=TENANT)

    by = {r["input_source"]: r for r in rows}
    assert set(by) == {"user_prompt", "retrieved_document", "tool_output"}

    up = by["user_prompt"]
    assert up["total"] == 2 and up["allowed"] == 2
    assert up["attacks"] == 0
    assert up["threats"] == {}

    rd = by["retrieved_document"]
    assert rd["total"] == 3
    assert rd["blocked"] == 2 and rd["sanitized"] == 1
    assert rd["attacks"] == 3               # 2 blocked + 1 sanitized
    assert rd["block_rate"] == round(2 / 3, 4)
    assert rd["high_risk_count"] == 2       # two rows >= 0.7
    assert rd["max_risk"] == 0.95
    assert rd["threats"] == {"PROMPT_INJECTION": 2, "JAILBREAK": 1}


@pytest.mark.asyncio
async def test_by_source_sorted_by_volume(test_db):
    await _seed(test_db)
    repo   = AuditRepository(test_db)
    rows   = await repo.get_stats_by_source(tenant_id=TENANT)
    totals = [r["total"] for r in rows]
    assert totals == sorted(totals, reverse=True)
