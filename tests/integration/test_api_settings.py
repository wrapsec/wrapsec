# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import pytest


@pytest.mark.asyncio
async def test_get_thresholds_returns_defaults(client, admin_headers):
    response = await client.get("/v1/settings/thresholds", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert "block_threshold" in data
    assert "sanitize_threshold" in data
    assert data["block_threshold"] > data["sanitize_threshold"]


@pytest.mark.asyncio
async def test_update_thresholds(client, admin_jwt_headers):
    response = await client.put(
        "/v1/settings/thresholds",
        json={"block_threshold": 0.75, "sanitize_threshold": 0.45},
        headers=admin_jwt_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["block_threshold"] == 0.75
    assert data["sanitize_threshold"] == 0.45
    assert "updated_at" in data


@pytest.mark.asyncio
async def test_invalid_thresholds_rejected(client, admin_jwt_headers):
    response = await client.put(
        "/v1/settings/thresholds",
        json={"block_threshold": 0.3, "sanitize_threshold": 0.5},
        headers=admin_jwt_headers,
    )
    assert response.status_code in (400, 422)


@pytest.mark.asyncio
async def test_get_layers_returns_defaults(client, admin_headers):
    response = await client.get("/v1/settings/layers", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert "rule_enabled" in data
    assert "ml_enabled" in data
    assert "llm_enabled" in data


@pytest.mark.asyncio
async def test_update_layers(client, admin_jwt_headers):
    response = await client.put(
        "/v1/settings/layers",
        json={"llm_enabled": False},
        headers=admin_jwt_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["llm_enabled"] is False
    assert data["rule_enabled"] is True
    assert "updated_at" in data


# ── Thresholds: merge-invalid path (schema passes, merged state fails) ────────

@pytest.mark.asyncio
async def test_thresholds_merge_produces_invalid_state_rejected(client, admin_jwt_headers):
    # Store a high sanitize first (valid against its own block) ...
    await client.put(
        "/v1/settings/thresholds",
        json={"block_threshold": 0.9, "sanitize_threshold": 0.6},
        headers=admin_jwt_headers,
    )
    # ... then update ONLY block to a value that passes the schema (validated against the
    # system-default sanitize) but is <= the STORED sanitize once merged -> rejected.
    r = await client.put(
        "/v1/settings/thresholds",
        json={"block_threshold": 0.5},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422


# ── LLM settings (encryption / masking / validation) ─────────────────────────

@pytest.mark.asyncio
async def test_get_llm_settings_default_has_no_key(client, admin_headers):
    r = await client.get("/v1/settings/llm", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "provider" in data and "model" in data
    assert data["api_key_masked"] is None


@pytest.mark.asyncio
async def test_update_llm_settings_merges_fields(client, admin_jwt_headers):
    r = await client.put(
        "/v1/settings/llm",
        json={"provider": "openai", "model": "gpt-4o", "timeout": 30, "llm_trigger": 0.2},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["provider"] == "openai"
    assert data["model"] == "gpt-4o"
    assert data["timeout"] == 30
    assert data["llm_trigger"] == 0.2


@pytest.mark.asyncio
async def test_update_llm_api_key_is_encrypted_and_masked(client, admin_jwt_headers):
    r = await client.put(
        "/v1/settings/llm",
        json={"provider": "openai", "api_key": "sk-secret-value-123"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200, r.text
    masked = r.json()["api_key_masked"]
    assert masked is not None
    assert masked != "sk-secret-value-123"          # never echoes plaintext

    g = await client.get("/v1/settings/llm", headers=admin_jwt_headers)
    assert g.json()["api_key_masked"] is not None
    assert "sk-secret-value-123" not in g.text       # decrypt+mask, never plaintext


@pytest.mark.asyncio
async def test_update_llm_empty_api_key_clears_it(client, admin_jwt_headers):
    await client.put("/v1/settings/llm", json={"api_key": "sk-to-clear"}, headers=admin_jwt_headers)
    r = await client.put("/v1/settings/llm", json={"api_key": ""}, headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["api_key_masked"] is None


@pytest.mark.asyncio
async def test_update_llm_invalid_provider_rejected(client, admin_jwt_headers):
    r = await client.put("/v1/settings/llm", json={"provider": "bogus"}, headers=admin_jwt_headers)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_update_llm_invalid_timeout_rejected(client, admin_jwt_headers):
    r = await client.put("/v1/settings/llm", json={"timeout": 3}, headers=admin_jwt_headers)
    assert r.status_code == 422


# ── Retention ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_retention_default_source_environment(client, admin_headers):
    r = await client.get("/v1/settings/retention", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["source"] == "environment"


@pytest.mark.asyncio
async def test_update_then_get_retention_reports_database(client, admin_jwt_headers):
    p = await client.put("/v1/settings/retention", json={"retention_days": 30}, headers=admin_jwt_headers)
    assert p.status_code == 200, p.text
    assert p.json()["retention_days"] == 30
    g = await client.get("/v1/settings/retention", headers=admin_jwt_headers)
    assert g.json()["retention_days"] == 30
    assert g.json()["source"] == "database"


@pytest.mark.asyncio
async def test_update_retention_below_minimum_rejected(client, admin_jwt_headers):
    r = await client.put("/v1/settings/retention", json={"retention_days": 5}, headers=admin_jwt_headers)
    assert r.status_code == 422


# ── Rate limit ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_rate_limit_default_source_environment(client, admin_headers):
    r = await client.get("/v1/settings/rate_limit", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["source"] == "environment"


@pytest.mark.asyncio
async def test_update_then_get_rate_limit_reports_database(client, admin_jwt_headers):
    p = await client.put("/v1/settings/rate_limit", json={"per_minute": 120}, headers=admin_jwt_headers)
    assert p.status_code == 200, p.text
    assert p.json()["per_minute"] == 120
    assert p.json()["source"] == "database"
    g = await client.get("/v1/settings/rate_limit", headers=admin_jwt_headers)
    assert g.json()["per_minute"] == 120
    assert g.json()["source"] == "database"


@pytest.mark.asyncio
async def test_update_rate_limit_below_one_rejected(client, admin_jwt_headers):
    r = await client.put("/v1/settings/rate_limit", json={"per_minute": 0}, headers=admin_jwt_headers)
    assert r.status_code == 422


# ── Storage (read-only, env-driven) ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_storage_settings(client, admin_headers):
    r = await client.get("/v1/settings/storage", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "storage_mode" in data
    assert "retention_days_proxy" in data


# ── Admin limits (audit-logged on change) ────────────────────────────────────

@pytest.mark.asyncio
async def test_get_admin_limits_default_source_environment(client, admin_headers):
    r = await client.get("/v1/settings/admin_limits", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["source"] == "environment"


@pytest.mark.asyncio
async def test_update_then_get_admin_limits_reports_database(client, admin_jwt_headers):
    p = await client.put(
        "/v1/settings/admin_limits",
        json={"admin_write_rate_limit": 50, "audit_export_rate_limit": 10},
        headers=admin_jwt_headers,
    )
    assert p.status_code == 200, p.text
    assert p.json()["admin_write_rate_limit"] == 50
    assert p.json()["source"] == "database"
    g = await client.get("/v1/settings/admin_limits", headers=admin_jwt_headers)
    assert g.json()["admin_write_rate_limit"] == 50
    assert g.json()["source"] == "database"


@pytest.mark.asyncio
async def test_update_admin_limits_below_floor_rejected(client, admin_jwt_headers):
    r = await client.put(
        "/v1/settings/admin_limits",
        json={"admin_write_rate_limit": 2},   # below the 5 floor
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422


# ── GET-after-PUT reflects stored values (the 'database' branch) ──────────────

@pytest.mark.asyncio
async def test_get_thresholds_reflects_stored_after_update(client, admin_jwt_headers):
    await client.put(
        "/v1/settings/thresholds",
        json={"block_threshold": 0.82, "sanitize_threshold": 0.33},
        headers=admin_jwt_headers,
    )
    g = await client.get("/v1/settings/thresholds", headers=admin_jwt_headers)
    assert g.json()["block_threshold"] == 0.82
    assert g.json()["sanitize_threshold"] == 0.33


@pytest.mark.asyncio
async def test_get_layers_reflects_stored_after_update(client, admin_jwt_headers):
    await client.put("/v1/settings/layers", json={"ml_enabled": False}, headers=admin_jwt_headers)
    g = await client.get("/v1/settings/layers", headers=admin_jwt_headers)
    assert g.json()["ml_enabled"] is False


# ── Validation boundaries on the security-config schemas ─────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"block_threshold": 1.5},                       # block > 1.0
    {"sanitize_threshold": 1.0},                    # sanitize >= 1.0
    {"block_threshold": 0.0},                       # block <= 0
    {"sanitize_threshold": -0.1},                   # sanitize < 0
])
async def test_threshold_bounds_rejected(client, admin_jwt_headers, payload):
    r = await client.put("/v1/settings/thresholds", json=payload, headers=admin_jwt_headers)
    assert r.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"timeout": 300},                               # timeout > 120
    {"llm_trigger": 1.5},                           # llm_trigger > 1.0
    {"base_url": "http://169.254.169.254/latest"},  # SSRF-unsafe base_url
])
async def test_llm_validation_boundaries_rejected(client, admin_jwt_headers, payload):
    r = await client.put("/v1/settings/llm", json=payload, headers=admin_jwt_headers)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_rate_limit_above_ceiling_rejected(client, admin_jwt_headers):
    r = await client.put("/v1/settings/rate_limit", json={"per_minute": 99999}, headers=admin_jwt_headers)
    assert r.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"admin_write_rate_limit": 500},    # > 200 ceiling
    {"audit_export_rate_limit": 0},     # < 1 floor
    {"audit_export_rate_limit": 100},   # > 60 ceiling
])
async def test_admin_limits_boundaries_rejected(client, admin_jwt_headers, payload):
    r = await client.put("/v1/settings/admin_limits", json=payload, headers=admin_jwt_headers)
    assert r.status_code == 422
