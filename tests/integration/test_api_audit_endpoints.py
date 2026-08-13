# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration coverage for the audit read endpoints (mounted at /v1/audit).

/logs basics, /stats rates + tz/p95/JSONB regressions, and /by-source are
covered in test_api_audit / test_api_audit_pg / test_api_by_source. This file
targets what those do not: the three fully-untested endpoints (/attribution,
/analytics, /export CSV) plus the /logs enrichment (dept/app/proxy joins),
date and UUID validation, sort, and trace_id filter, and the /stats zero and
severity-breakdown branches.

Rows are seeded directly on audit_logs (the per-test-truncating client/test_db
harness isolates them) and read back via the admin api key, which sees the
whole tenant space.
"""

import uuid

import pytest

from db.models import AuditLogModel
from services.time import utc_now


def _row(**kw) -> AuditLogModel:
    base = {
        "id": uuid.uuid4(), "trace_id": "t-" + uuid.uuid4().hex[:16],
        "decision": "ALLOW", "risk_score": 0.1, "threats": [],
        "input_hash": "h", "detection_mode": "standard", "execution_mode": "scan",
        "llm_invoked": False, "latency_ms": 10.0, "source": "api",
        "input_source": "user_prompt", "created_at": utc_now(),
    }
    base.update(kw)
    return AuditLogModel(**base)


# ── /attribution ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_attribution_groups_by_key_dept_app_reason_band(client, admin_headers, test_db):
    did, aid, kid = str(uuid.uuid4()), str(uuid.uuid4()), "key_attr"
    test_db.add_all([
        _row(decision="BLOCK", key_id=kid, dept_id=did, app_id=aid,
             primary_reason="prompt_injection", confidence_band="high"),
        _row(decision="ALLOW", key_id=kid, dept_id=did, app_id=aid,
             primary_reason="clean", confidence_band="low"),
    ])
    await test_db.commit()

    r = await client.get("/v1/audit/attribution", headers=admin_headers)
    assert r.status_code == 200, r.text
    d = r.json()
    by_key = {k["key_id"]: k for k in d["by_key"]}
    assert by_key[kid]["total"] == 2
    assert by_key[kid]["blocked"] == 1
    assert by_key[kid]["block_rate"] == 0.5
    assert {x["dept_id"]: x["total"] for x in d["by_department"]}[did] == 2
    assert {x["app_id"]: x["total"] for x in d["by_application"]}[aid] == 2
    assert {x["primary_reason"]: x["count"] for x in d["by_primary_reason"]}["prompt_injection"] == 1
    assert {x["band"]: x["count"] for x in d["by_confidence_band"]}["high"] == 1


@pytest.mark.asyncio
async def test_attribution_empty_returns_empty_lists(client, admin_headers):
    r = await client.get("/v1/audit/attribution", headers=admin_headers)
    assert r.status_code == 200
    d = r.json()
    assert d["by_key"] == []
    assert d["by_department"] == []
    assert d["by_application"] == []


# ── /analytics ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analytics_time_series_trend(client, admin_headers, test_db):
    test_db.add_all([
        _row(decision="BLOCK", risk_score=0.9),
        _row(decision="ALLOW", risk_score=0.1),
        _row(decision="SANITIZE", risk_score=0.5),
    ])
    await test_db.commit()

    r = await client.get("/v1/audit/analytics?group_by=day", headers=admin_headers)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["group_by"] == "day"
    assert d["total"] == 3
    assert d["block_rate"] == round(1 / 3, 3)
    # All three rows fall in one period (seeded at ~now).
    period = d["trend"][0]
    assert period["total"] == 3
    assert period["blocked"] == 1
    assert period["sanitized"] == 1
    assert period["allowed"] == 1


@pytest.mark.asyncio
async def test_analytics_invalid_group_by_422(client, admin_headers):
    r = await client.get("/v1/audit/analytics?group_by=year", headers=admin_headers)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_analytics_empty(client, admin_headers):
    r = await client.get("/v1/audit/analytics", headers=admin_headers)
    assert r.status_code == 200
    d = r.json()
    assert d["total"] == 0
    assert d["block_rate"] == 0.0
    assert d["trend"] == []


# ── /export (CSV) ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_csv_streams_with_pii_protections(client, admin_headers, test_db):
    test_db.add(_row(
        decision="BLOCK", risk_score=0.9, ip_address="8.8.8.8",
        user_id="user-1234567890", threats=["prompt_injection"],
    ))
    await test_db.commit()

    r = await client.get("/v1/audit/export", headers=admin_headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "wrapsec_audit_export.csv" in r.headers["content-disposition"]
    lines = [ln for ln in r.text.splitlines() if ln.strip()]
    assert lines[0].startswith("trace_id,")   # header row
    assert len(lines) == 2                      # header + one data row
    # PII protections: raw ip is hashed, user_id is truncated to an 8-char prefix.
    assert "8.8.8.8" not in r.text
    assert "user-1234567890" not in r.text
    assert "user-123" in r.text


@pytest.mark.asyncio
async def test_export_empty_returns_header_only(client, admin_headers):
    r = await client.get("/v1/audit/export", headers=admin_headers)
    assert r.status_code == 200
    lines = [ln for ln in r.text.splitlines() if ln.strip()]
    assert len(lines) == 1
    assert lines[0].startswith("trace_id,")


# ── /logs: enrichment joins ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logs_enriches_dept_and_app_names(client, admin_headers, test_db):
    from db.models import ApplicationModel, DepartmentModel, TenantModel
    tid, did, aid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T", global_policy={}, is_active=True))
    await test_db.commit()
    test_db.add(DepartmentModel(id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}", name="Eng", is_active=True))
    await test_db.commit()
    test_db.add(ApplicationModel(id=aid, tenant_id=tid, dept_id=did, slug=f"a-{aid.hex[:6]}", name="Chatbot", is_active=True))
    await test_db.commit()
    test_db.add(_row(tenant_id=str(tid), dept_id=str(did), app_id=str(aid)))
    await test_db.commit()

    r = await client.get("/v1/audit/logs", headers=admin_headers)
    assert r.status_code == 200
    item = r.json()["items"][0]
    assert item["dept_name"] == "Eng"
    assert item["app_name"] == "Chatbot"


@pytest.mark.asyncio
async def test_logs_enriches_proxy_interaction(client, admin_headers, test_db):
    from db.models import ProxyInteractionModel
    pid = uuid.uuid4()
    test_db.add(ProxyInteractionModel(
        id=pid, trace_id="px-" + uuid.uuid4().hex[:10],
        input_decision="ALLOW", input_primary_reason="clean", input_confidence=0.1,
        execution_status="completed", total_latency_ms=100,
        output_decision="ALLOW", provider="openai", model="gpt-4o",
    ))
    await test_db.commit()
    test_db.add(_row(proxy_interaction_id=pid))
    await test_db.commit()

    r = await client.get("/v1/audit/logs", headers=admin_headers)
    item = r.json()["items"][0]
    assert item["provider"] == "openai"
    assert item["model"] == "gpt-4o"
    assert item["output_decision"] == "ALLOW"


# ── /logs: validation + sort + filter branches ───────────────────────────────

@pytest.mark.asyncio
async def test_logs_invalid_date_rejected(client, admin_headers):
    r = await client.get("/v1/audit/logs?from=not-a-date", headers=admin_headers)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_logs_invalid_user_id_uuid_rejected(client, admin_headers):
    # M6: the user_id filter is UUID-strict to close the substring-probe path.
    r = await client.get("/v1/audit/logs?user_id=not-a-uuid", headers=admin_headers)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_logs_sort_by_risk_score_ascending(client, admin_headers, test_db):
    test_db.add_all([_row(risk_score=0.9), _row(risk_score=0.1), _row(risk_score=0.5)])
    await test_db.commit()
    r = await client.get("/v1/audit/logs?sort_by=risk_score&sort_order=asc", headers=admin_headers)
    scores = [i["risk_score"] for i in r.json()["items"]]
    assert scores == sorted(scores)


@pytest.mark.asyncio
async def test_logs_filter_by_trace_id(client, admin_headers, test_db):
    test_db.add_all([_row(trace_id="findme-xyz"), _row(trace_id="other-row")])
    await test_db.commit()
    r = await client.get("/v1/audit/logs?trace_id=findme-xyz", headers=admin_headers)
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["trace_id"] == "findme-xyz"


# ── /stats: zero + severity breakdown ────────────────────────────────────────

@pytest.mark.asyncio
async def test_stats_empty_returns_zeros(client, admin_headers):
    r = await client.get("/v1/audit/stats", headers=admin_headers)
    assert r.status_code == 200
    d = r.json()
    assert d["total_requests"] == 0
    assert d["block_rate"] == 0.0
    assert d["top_threats"] == []
    assert d["severity_counts"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


@pytest.mark.asyncio
async def test_stats_severity_counts_sum_to_total(client, admin_headers, test_db):
    # /stats groups the stored severity column (the production writer populates
    # it), so seed it explicitly here.
    test_db.add_all([
        _row(decision="BLOCK", risk_score=0.95, primary_reason="prompt_injection", severity="CRITICAL"),
        _row(decision="BLOCK", risk_score=0.9, primary_reason="jailbreak", severity="HIGH"),
        _row(decision="ALLOW", risk_score=0.05, severity="LOW"),
    ])
    await test_db.commit()
    r = await client.get("/v1/audit/stats", headers=admin_headers)
    d = r.json()
    assert d["total_requests"] == 3
    assert d["block_count"] == 2
    assert d["severity_counts"]["CRITICAL"] == 1
    assert d["severity_counts"]["HIGH"] == 1
    assert d["severity_counts"]["LOW"] == 1
