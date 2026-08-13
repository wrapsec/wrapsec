# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
PostgreSQL-only regression tests for /v1/audit/stats.

Motivation: v1.2.1 shipped two bugs in this endpoint that the SQLite-backed
`client` fixture could never have caught:

  1. `jsonb_array_elements_text` -- the top-threats aggregation uses a jsonb
     function that does not exist in SQLite.
  2. asyncpg refuses to bind a tz-aware datetime against a TIMESTAMP WITHOUT
     TIME ZONE column, but SQLite's driver silently coerces, so the from/to
     range filter looked healthy in tests and returned 500 in prod.

These tests use the pg_client fixture (see tests/integration/conftest.py) so
the queries actually run against PostgreSQL. Marked `pg` so runs without a
reachable DB skip cleanly instead of failing.
"""

import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest
import pytest_asyncio

from db.models import AuditLogModel

pytestmark = pytest.mark.pg


@pytest_asyncio.fixture
async def seeded_audit_rows(pg_db):
    """
    Seeds a mixed set of audit rows so the aggregation paths have data to
    aggregate. Uses a random tenant_id so the row set is isolated even when
    pg_client is pointed at a shared PG (WRAPSEC_TEST_PG_URL).
    """
    tenant_id = str(uuid.uuid4())
    dept_id   = str(uuid.uuid4())
    # Aware UTC: created_at is TIMESTAMPTZ, so seed the same aware instants the
    # production writer (utc_now) produces, or the aware date-range filter in
    # /v1/audit/stats will not match naive-bound rows.
    now       = datetime.now(timezone.utc)

    rows = [
        AuditLogModel(
            id=uuid.uuid4(), trace_id=f"t-{i}-{uuid.uuid4().hex[:6]}",
            decision=decision, risk_score=score, threats=threats,
            input_hash=f"sha256:{uuid.uuid4().hex}",
            detection_mode="standard", execution_mode="scan",
            llm_invoked=False, latency_ms=latency,
            tenant_id=tenant_id, dept_id=dept_id, source="api",
            created_at=now - timedelta(minutes=i),
        )
        for i, (decision, score, threats, latency) in enumerate([
            ("BLOCK",    0.92, ["PROMPT_INJECTION"],              45.0),
            ("BLOCK",    0.85, ["PROMPT_INJECTION", "JAILBREAK"], 60.0),
            ("SANITIZE", 0.55, ["PII_DETECTED"],                  30.0),
            ("ALLOW",    0.10, [],                                12.0),
            ("ALLOW",    0.05, [],                                18.0),
        ])
    ]
    for r in rows:
        pg_db.add(r)
    await pg_db.commit()
    return {"tenant_id": tenant_id, "dept_id": dept_id, "count": len(rows)}


@pytest.mark.asyncio
async def test_stats_jsonb_top_threats_returns_counts(
    pg_client, admin_headers, seeded_audit_rows,
):
    """
    Regression for the v1.2.1 top-threats aggregation. Proves that
    `jsonb_array_elements_text` unnests the threats array and returns real
    per-category counts. SQLite fell through to the Python path, so a typo or
    a missing function name in the PG branch would never surface in tests
    before this fixture existed.
    """
    r = await pg_client.get(
        f"/v1/audit/stats?tenant_id={seeded_audit_rows['tenant_id']}",
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()

    threats = {row["category"]: row["count"] for row in body["top_threats"]}
    assert threats.get("PROMPT_INJECTION") == 2
    assert threats.get("JAILBREAK")        == 1
    assert threats.get("PII_DETECTED")     == 1


@pytest.mark.asyncio
async def test_stats_with_tz_aware_date_range_does_not_500(
    pg_client, admin_headers, seeded_audit_rows,
):
    """
    Regression for the v1.2.1 asyncpg tz-aware bind. `_parse_dt` produces a
    tz-aware datetime from an ISO string carrying `Z` or an offset. Prior to
    v1.2.1 that value was passed as-is against audit_logs.created_at, which
    is TIMESTAMP WITHOUT TIME ZONE; asyncpg rejected the bind with
    "can't subtract offset-naive and offset-aware datetimes" and the endpoint
    returned 500. SQLite silently coerces, so integration tests passed.
    """
    # `Z` for one bound and a URL-encoded `+00:00` for the other so both
    # tz-aware ISO forms exercise the tz-strip logic in the repo/endpoint.
    from_iso = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"
    to_iso   = quote(
        (datetime.utcnow() + timedelta(hours=1)).isoformat() + "+00:00",
        safe="",
    )

    r = await pg_client.get(
        f"/v1/audit/stats"
        f"?tenant_id={seeded_audit_rows['tenant_id']}"
        f"&from={from_iso}&to={to_iso}",
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_requests"] == seeded_audit_rows["count"]


@pytest.mark.asyncio
async def test_stats_p95_uses_percentile_cont(
    pg_client, admin_headers, seeded_audit_rows,
):
    """
    On PG, p95_latency_ms is computed via percentile_cont(0.95). The seeded
    latencies span 12-60ms; p95 should be in the upper band. This also proves
    the SQL branch executes (SQLite path returns 0 for a single-row set with
    the int() index).
    """
    r = await pg_client.get(
        f"/v1/audit/stats?tenant_id={seeded_audit_rows['tenant_id']}",
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert 40.0 <= body["p95_latency_ms"] <= 60.0


@pytest.mark.asyncio
async def test_stats_dept_scope_filters_aggregates(pg_client, pg_db, admin_headers):
    """
    Regression for the v1.2.2 cross-dept aggregate leak. The `dept_id`
    argument added to AuditRepository.get_stats must actually filter the
    aggregate query, not just the severity_counts inline query. Seed two
    depts under the same tenant, aggregate against one, and assert the
    counts match that dept alone.
    """
    tenant_id = str(uuid.uuid4())
    dept_a    = str(uuid.uuid4())
    dept_b    = str(uuid.uuid4())

    for dept, decisions in [(dept_a, ["BLOCK", "BLOCK", "ALLOW"]),
                            (dept_b, ["ALLOW", "ALLOW"])]:
        for i, decision in enumerate(decisions):
            pg_db.add(AuditLogModel(
                id=uuid.uuid4(),
                trace_id=f"scope-{dept[:6]}-{i}-{uuid.uuid4().hex[:6]}",
                decision=decision, risk_score=0.5, threats=[],
                input_hash=f"sha256:{uuid.uuid4().hex}",
                detection_mode="standard", execution_mode="scan",
                llm_invoked=False, latency_ms=20.0,
                tenant_id=tenant_id, dept_id=dept, source="api",
            ))
    await pg_db.commit()

    # Admin key sees the full tenant (no dept_id in scope).
    r = await pg_client.get(
        f"/v1/audit/stats?tenant_id={tenant_id}",
        headers=admin_headers,
    )
    assert r.status_code == 200
    assert r.json()["total_requests"] == 5

    # The endpoint's dept-scoping path is exercised via non-admin API keys.
    # The repository-level filter is the same code path, so validate it
    # directly here to keep this test standalone (no key/user seeding).
    from db.repositories.audit import AuditRepository
    repo = AuditRepository(pg_db)
    stats_a = await repo.get_stats(tenant_id=tenant_id, dept_id=dept_a)
    stats_b = await repo.get_stats(tenant_id=tenant_id, dept_id=dept_b)

    assert stats_a["total"]       == 3
    assert stats_a["block_count"] == 2
    assert stats_a["allow_count"] == 1

    assert stats_b["total"]       == 2
    assert stats_b["allow_count"] == 2
    assert stats_b["block_count"] == 0
