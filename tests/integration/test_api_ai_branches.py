# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration coverage for the branch logic in the scan endpoint (/v1/ai) that the
core tests (test_api_ai / test_api_scan_batch) do not reach: trial-key
restrictions, the per-app rate-limit path, the proxy-requires-LLM guard, and the
GET /v1/ai/requests/{trace_id} dept/app name enrichment + proxy-interaction join.

Requests authenticate with real hash-matching API keys seeded per test, so
request.state carries the key's key_type / dept / app scope into the handler.
"""

import hashlib
import uuid

import pytest

from services.time import utc_now


async def _seed_key(test_db, *, key_type="live", with_app=False,
                    rate_limit_override=None, dept_policy_override=None):
    """Seed a usable (hash-matching) non-admin API key and return (raw_key, ids)."""
    from db.models import APIKeyModel, ApplicationModel, DepartmentModel, TenantModel

    tid, did = uuid.uuid4(), uuid.uuid4()
    aid = uuid.uuid4() if with_app else None
    prefix = "wsk_trial_" if key_type == "trial" else "wsk_live_"
    raw = prefix + uuid.uuid4().hex

    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await test_db.commit()
    test_db.add(DepartmentModel(id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}", name="Eng",
                                is_active=True, policy_override=dept_policy_override))
    await test_db.commit()
    if with_app:
        test_db.add(ApplicationModel(id=aid, tenant_id=tid, dept_id=did, slug=f"a-{aid.hex[:6]}",
                                     name="Chatbot", is_active=True, rate_limit_override=rate_limit_override))
        await test_db.commit()
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:8],
        tenant_id=tid, dept_id=did, app_id=aid, name="k",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type=key_type, is_admin=False, revoked=False,
    ))
    await test_db.commit()
    return raw, {"tenant_id": tid, "dept_id": did, "app_id": aid}


def _audit_row(*, trace_id, dept_id=None, app_id=None, tenant_id=None,
               proxy_interaction_id=None, execution_mode="scan"):
    from db.models import AuditLogModel
    return AuditLogModel(
        id=uuid.uuid4(), trace_id=trace_id, decision="ALLOW", risk_score=0.1, threats=[],
        input_hash="h", detection_mode="standard", execution_mode=execution_mode,
        llm_invoked=False, latency_ms=10.0, source="api", input_source="user_prompt",
        dept_id=dept_id, app_id=app_id, tenant_id=tenant_id,
        proxy_interaction_id=proxy_interaction_id, created_at=utc_now(),
    )


# ── trial-key restrictions ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_trial_key_input_cap_rejected(client, test_db):
    raw, _ = await _seed_key(test_db, key_type="trial")
    # 600 chars exceeds the 500 trial cap but is under the 8000 global cap, so the
    # trial-specific limit (not the schema limit) is what rejects it.
    r = await client.post("/v1/ai/request", json={"input": "a" * 600}, headers={"x-api-key": raw})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_trial_key_proxy_mode_forbidden(client, test_db):
    raw, _ = await _seed_key(test_db, key_type="trial")
    r = await client.post(
        "/v1/ai/request",
        json={"input": "hello", "execution_mode": "proxy", "model": "gpt-4o"},
        headers={"x-api-key": raw},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_trial_key_normal_scan_allowed(client, test_db):
    raw, _ = await _seed_key(test_db, key_type="trial")
    r = await client.post("/v1/ai/request", json={"input": "hello world"}, headers={"x-api-key": raw})
    assert r.status_code == 200
    assert r.json()["decision"] in ("ALLOW", "SANITIZE", "BLOCK")


@pytest.mark.asyncio
async def test_batch_trial_key_item_cap_rejected(client, test_db):
    # The single-scan trial cap also applies per batch item.
    raw, _ = await _seed_key(test_db, key_type="trial")
    body = {"items": [{"id": "big", "input": "a" * 600}]}
    r = await client.post("/v1/ai/scan-batch", json=body, headers={"x-api-key": raw})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


# ── per-app rate-limit path (app scope + rate_limit_override) ─────────────────

@pytest.mark.asyncio
async def test_app_scoped_key_with_rate_limit_override_scans(client, test_db):
    # An app-scoped key whose app carries a rate_limit_override drives the
    # per-app bucket check (not tripped by a single request).
    raw, _ = await _seed_key(test_db, with_app=True, rate_limit_override=250)
    r = await client.post("/v1/ai/request", json={"input": "hello"}, headers={"x-api-key": raw})
    assert r.status_code == 200


# ── proxy-requires-LLM guard ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_proxy_mode_requires_llm_layer_422(client, test_db):
    # Department override disables the LLM layer; proxy mode then cannot run.
    raw, _ = await _seed_key(test_db, dept_policy_override={"detection": {"llm_enabled": False}})
    r = await client.post(
        "/v1/ai/request",
        json={"input": "hello", "execution_mode": "proxy", "model": "gpt-4o"},
        headers={"x-api-key": raw},
    )
    assert r.status_code == 422


# ── GET /requests/{trace_id}: enrichment + proxy join ────────────────────────

@pytest.mark.asyncio
async def test_get_request_enriches_dept_and_app_names(client, admin_headers, test_db):
    from db.models import ApplicationModel, DepartmentModel, TenantModel
    tid, did, aid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await test_db.commit()
    test_db.add(DepartmentModel(id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}", name="Eng", is_active=True))
    await test_db.commit()
    test_db.add(ApplicationModel(id=aid, tenant_id=tid, dept_id=did, slug=f"a-{aid.hex[:6]}", name="Chatbot", is_active=True))
    await test_db.commit()
    trace = "tr-" + uuid.uuid4().hex[:12]
    test_db.add(_audit_row(trace_id=trace, dept_id=str(did), app_id=str(aid), tenant_id=str(tid)))
    await test_db.commit()

    r = await client.get(f"/v1/ai/requests/{trace}", headers=admin_headers)
    assert r.status_code == 200, r.text
    attr = r.json()["attribution"]
    assert attr["dept_name"] == "Eng"
    assert attr["app_name"] == "Chatbot"


@pytest.mark.asyncio
async def test_get_request_includes_proxy_interaction(client, admin_headers, test_db):
    from db.models import ProxyInteractionModel
    pid = uuid.uuid4()
    test_db.add(ProxyInteractionModel(
        id=pid, trace_id="px-" + uuid.uuid4().hex[:10],
        input_decision="ALLOW", input_primary_reason="clean", input_confidence=0.1,
        execution_status="completed", total_latency_ms=120,
        provider="openai", model="gpt-4o", output_decision="ALLOW",
    ))
    await test_db.commit()
    trace = "tr-" + uuid.uuid4().hex[:12]
    test_db.add(_audit_row(trace_id=trace, proxy_interaction_id=pid, execution_mode="proxy"))
    await test_db.commit()

    r = await client.get(f"/v1/ai/requests/{trace}", headers=admin_headers)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["is_proxy"] is True
    assert d["proxy"]["provider"] == "openai"
    assert d["proxy"]["model"] == "gpt-4o"
    assert d["proxy"]["execution_status"] == "completed"


# ── B2: semantic-cache hits are audited too ──────────────────────────────────

@pytest.mark.asyncio
async def test_cache_hit_writes_audit_row(client, test_db):
    # Force a cache hit deterministically (no Redis dependency) by patching the
    # lookup to return a cached ALLOW body. The endpoint must still write a
    # tenant-attributed, hash-chained audit row for it.
    from unittest.mock import AsyncMock, patch

    from sqlalchemy import select

    from db.models import AuditLogModel

    raw, ids = await _seed_key(test_db)
    cached_body = {
        "trace_id":        "orig-trace",
        "decision":        "ALLOW",
        "risk_score":      0.05,
        "primary_reason":  "NO_THREAT_DETECTED",
        "confidence":      0.9,
        "confidence_band": "HIGH",
        "threats":         [],
        "processing":      {"llm_invoked": False, "latency_ms": 2.0},
    }
    with patch("cache.semantic_cache.get_cached_result", AsyncMock(return_value=cached_body)):
        r = await client.post("/v1/ai/request", json={"input": "hello world"}, headers={"x-api-key": raw})

    assert r.status_code == 200
    rows = (await test_db.execute(
        select(AuditLogModel).where(AuditLogModel.tenant_id == str(ids["tenant_id"]))
    )).scalars().all()
    assert len(rows) == 1                       # the cache hit produced an audit row
    row = rows[0]
    assert row.policy_source == "cache"
    assert row.decision == "ALLOW"
    assert row.record_hash is not None          # tenant-attributed -> hash-chained
