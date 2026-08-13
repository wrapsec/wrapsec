# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration coverage for the department admin endpoints (mounted at
/v1/admin/departments). Slug canonicalization, cross-tenant 404 guards, and RBAC
are exercised in test_api_slug / test_cross_tenant_isolation / test_rbac_role_matrix;
this file targets the handler logic those do not: stats aggregation, effective-
policy resolution, secret masking on read, partial update + policy clear, the
LLM/proxy override PATCH endpoints (encrypt/mask/clear/validate), and soft delete.
"""

import uuid

import pytest

from config.settings import get_settings
from security.encryption import encrypt

BASE = "/v1/admin/departments"


def _admin_tenant_id(admin_jwt_headers) -> uuid.UUID:
    from services.auth.token import decode_access_token
    token = admin_jwt_headers["Authorization"].split()[1]
    return uuid.UUID(decode_access_token(token)["tenant_id"])


async def _create_dept(client, headers, *, slug, name="Dept", policy_override=None):
    r = await client.post(
        BASE,
        json={"slug": slug, "name": name, "policy_override": policy_override},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _seed_dept(test_db, tenant_id, *, policy_override=None):
    """Insert a department directly (used when it must carry a pre-encrypted
    policy_override). Returns dept_id (str)."""
    from db.models import DepartmentModel
    did = uuid.uuid4()
    test_db.add(DepartmentModel(
        id=did, tenant_id=tenant_id, slug=f"seed-{did.hex[:6]}",
        name="Seed", is_active=True, policy_override=policy_override,
    ))
    await test_db.commit()
    return str(did)


def _audit_row(dept_id, *, decision, latency, threats=None):
    from db.models import AuditLogModel
    return AuditLogModel(
        id=uuid.uuid4(), trace_id="tr-" + uuid.uuid4().hex[:16],
        decision=decision, risk_score=0.5, threats=threats or [],
        input_hash="h", detection_mode="standard", execution_mode="scan",
        latency_ms=latency, dept_id=dept_id,
    )


# ── create + list ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_department_success(client, admin_jwt_headers):
    r = await client.post(BASE, json={"slug": "Payments Team", "name": "Payments"}, headers=admin_jwt_headers)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["slug"] == "payments-team"        # canonicalized server-side
    assert d["name"] == "Payments"
    assert d["application_count"] == 0


@pytest.mark.asyncio
async def test_list_departments_reports_application_count(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _create_dept(client, admin_jwt_headers, slug="with-apps")
    # Seed one active application under the dept so the count join is exercised.
    from db.models import ApplicationModel
    test_db.add(ApplicationModel(
        id=uuid.uuid4(), tenant_id=tid, dept_id=uuid.UUID(did),
        slug=f"a-{uuid.uuid4().hex[:6]}", name="App", is_active=True,
    ))
    await test_db.commit()

    r = await client.get(BASE, headers=admin_jwt_headers)
    assert r.status_code == 200
    match = [d for d in r.json()["departments"] if d["id"] == did]
    assert match and match[0]["application_count"] == 1


# ── get + secret masking ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_department_masks_encrypted_override_key(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    enc = encrypt("sk-super-secret-123", get_settings().secret_key)
    did = await _seed_dept(test_db, tid, policy_override={"llm": {"provider": "openai", "api_key_enc": enc}})

    r = await client.get(f"{BASE}/{did}", headers=admin_jwt_headers)
    assert r.status_code == 200
    llm = r.json()["policy_override"]["llm"]
    assert "api_key_enc" not in llm            # ciphertext never leaves the server
    assert llm["api_key_masked"]               # masked hint present
    assert "sk-super-secret-123" not in r.text  # plaintext never appears


@pytest.mark.asyncio
async def test_get_department_nonexistent_404(client, admin_jwt_headers):
    r = await client.get(f"{BASE}/{uuid.uuid4()}", headers=admin_jwt_headers)
    assert r.status_code == 404


# ── stats aggregation ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_department_stats_aggregates_audit_logs(client, admin_jwt_headers, test_db):
    did = await _create_dept(client, admin_jwt_headers, slug="stats-dept")
    test_db.add_all([
        _audit_row(did, decision="BLOCK", latency=10.0, threats=["prompt_injection"]),
        _audit_row(did, decision="BLOCK", latency=20.0, threats=["prompt_injection", "jailbreak"]),
        _audit_row(did, decision="ALLOW", latency=30.0, threats=[]),
        _audit_row(did, decision="ALLOW", latency=40.0, threats=["jailbreak"]),
    ])
    await test_db.commit()

    r = await client.get(f"{BASE}/{did}/stats", headers=admin_jwt_headers)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 4
    assert d["decisions"] == {"BLOCK": 2, "ALLOW": 2}
    assert d["block_rate"] == 0.5
    assert d["avg_latency_ms"] == 25.0
    # top_threats sorted by frequency: prompt_injection (2) before jailbreak (2)
    cats = {t["category"]: t["count"] for t in d["top_threats"]}
    assert cats["prompt_injection"] == 2
    assert cats["jailbreak"] == 2


@pytest.mark.asyncio
async def test_department_stats_empty_returns_zeros(client, admin_jwt_headers):
    did = await _create_dept(client, admin_jwt_headers, slug="empty-stats")
    r = await client.get(f"{BASE}/{did}/stats", headers=admin_jwt_headers)
    assert r.status_code == 200
    d = r.json()
    assert d["total"] == 0
    assert d["block_rate"] == 0.0
    assert d["top_threats"] == []


# ── effective policy resolution ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_department_policy_with_override(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _seed_dept(test_db, tid, policy_override={"detection": {"rule_enabled": False}})
    r = await client.get(f"{BASE}/{did}/policy", headers=admin_jwt_headers)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["override_set"] is True
    assert d["policy_source"] == "department_override"
    assert d["resolved_policy"]["detection"]["rule_enabled"] is False


@pytest.mark.asyncio
async def test_department_policy_without_override(client, admin_jwt_headers):
    did = await _create_dept(client, admin_jwt_headers, slug="no-override")
    r = await client.get(f"{BASE}/{did}/policy", headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["override_set"] is False
    assert "resolved_policy" in r.json()


# ── update (partial + policy clear + admin event) ────────────────────────────

@pytest.mark.asyncio
async def test_update_department_name(client, admin_jwt_headers):
    did = await _create_dept(client, admin_jwt_headers, slug="rename-me", name="Old")
    r = await client.put(f"{BASE}/{did}", json={"name": "New"}, headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["name"] == "New"


@pytest.mark.asyncio
async def test_update_department_clears_policy_override(client, admin_jwt_headers, test_db):
    tid = _admin_tenant_id(admin_jwt_headers)
    did = await _seed_dept(test_db, tid, policy_override={"detection": {"rule_enabled": False}})
    # Explicit null must be applied (exclude_unset) to clear the override; this
    # also drives the POLICY_OVERRIDE_CHANGED admin-event write path.
    r = await client.put(f"{BASE}/{did}", json={"policy_override": None}, headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["policy_override"] is None


@pytest.mark.asyncio
async def test_update_department_nonexistent_404(client, admin_jwt_headers):
    r = await client.put(f"{BASE}/{uuid.uuid4()}", json={"name": "X"}, headers=admin_jwt_headers)
    assert r.status_code == 404


# ── LLM detection override PATCH ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dept_llm_override_set_encrypts_and_masks(client, admin_jwt_headers):
    did = await _create_dept(client, admin_jwt_headers, slug="llm-set")
    r = await client.patch(
        f"{BASE}/{did}/policy/llm",
        json={"provider": "openai", "model": "gpt-4o", "api_key": "sk-llm-plaintext-xyz"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200, r.text
    llm = r.json()["policy_override"]["llm"]
    assert llm["provider"] == "openai"
    assert llm["api_key_masked"]
    assert "api_key_enc" not in llm
    assert "sk-llm-plaintext-xyz" not in r.text


@pytest.mark.asyncio
async def test_dept_llm_override_clear(client, admin_jwt_headers):
    did = await _create_dept(client, admin_jwt_headers, slug="llm-clear")
    await client.patch(f"{BASE}/{did}/policy/llm", json={"provider": "openai"}, headers=admin_jwt_headers)
    r = await client.patch(f"{BASE}/{did}/policy/llm", json={"clear": True}, headers=admin_jwt_headers)
    assert r.status_code == 200
    override = r.json()["policy_override"] or {}
    assert "llm" not in override


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"provider": "bogus"},                           # invalid provider
    {"timeout": 3},                                  # below 5s floor
    {"base_url": "http://169.254.169.254/latest"},   # SSRF-unsafe
])
async def test_dept_llm_override_validation_422(client, admin_jwt_headers, payload):
    did = await _create_dept(client, admin_jwt_headers, slug=f"llm-bad-{uuid.uuid4().hex[:6]}")
    r = await client.patch(f"{BASE}/{did}/policy/llm", json=payload, headers=admin_jwt_headers)
    assert r.status_code == 422


# ── proxy provider override PATCH ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dept_proxy_override_set_encrypts_and_masks(client, admin_jwt_headers):
    did = await _create_dept(client, admin_jwt_headers, slug="proxy-set")
    r = await client.patch(
        f"{BASE}/{did}/policy/proxy",
        json={"provider": "openai", "default_model": "gpt-4o", "api_key": "sk-proxy-plaintext-xyz"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200, r.text
    pp = r.json()["policy_override"]["proxy_provider"]
    assert pp["provider"] == "openai"
    assert pp["api_key_masked"]
    assert "api_key_enc" not in pp
    assert "sk-proxy-plaintext-xyz" not in r.text


@pytest.mark.asyncio
async def test_dept_proxy_override_clear(client, admin_jwt_headers):
    did = await _create_dept(client, admin_jwt_headers, slug="proxy-clear")
    await client.patch(f"{BASE}/{did}/policy/proxy", json={"provider": "openai"}, headers=admin_jwt_headers)
    r = await client.patch(f"{BASE}/{did}/policy/proxy", json={"clear": True}, headers=admin_jwt_headers)
    assert r.status_code == 200
    override = r.json()["policy_override"] or {}
    assert "proxy_provider" not in override


@pytest.mark.asyncio
async def test_dept_proxy_override_invalid_timeout_422(client, admin_jwt_headers):
    did = await _create_dept(client, admin_jwt_headers, slug="proxy-bad")
    r = await client.patch(
        f"{BASE}/{did}/policy/proxy",
        json={"timeout_seconds": 999},   # above the 300s ceiling
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422


# ── soft delete ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_department_soft_deletes(client, admin_jwt_headers, test_db):
    from db.models import DepartmentModel
    did = await _create_dept(client, admin_jwt_headers, slug="to-delete")
    r = await client.delete(f"{BASE}/{did}", headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["deactivated"] is True
    # Soft delete: the row is retained for audit history but flagged inactive ...
    row = await test_db.get(DepartmentModel, uuid.UUID(did))
    assert row is not None and row.is_active is False
    # ... and the active-scoped read endpoint no longer serves it.
    g = await client.get(f"{BASE}/{did}", headers=admin_jwt_headers)
    assert g.status_code == 404


@pytest.mark.asyncio
async def test_delete_department_nonexistent_404(client, admin_jwt_headers):
    r = await client.delete(f"{BASE}/{uuid.uuid4()}", headers=admin_jwt_headers)
    assert r.status_code == 404
