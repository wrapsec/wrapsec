# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration coverage for the health/readiness endpoints (mounted at the root:
/health, /health/live, /health/ready, /health/config).
"""

import pytest


@pytest.mark.asyncio
async def test_health_ok(client):
    r = await client.get("/health")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "ok"
    assert "version" in d


@pytest.mark.asyncio
async def test_health_live(client):
    r = await client.get("/health/live")
    assert r.status_code == 200
    assert r.json()["status"] == "alive"


@pytest.mark.asyncio
async def test_health_ready_reports_component_checks(client):
    r = await client.get("/health/ready")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] in ("ready", "degraded")
    assert set(d["checks"]) == {"database", "redis", "tfidf_detector", "transformer_detector"}
    # The disposable Postgres is up during the integration tier.
    assert d["checks"]["database"] == "ok"


@pytest.mark.asyncio
async def test_health_config_requires_auth(client):
    r = await client.get("/health/config")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_health_config_returns_effective_settings(client, admin_headers):
    r = await client.get("/health/config", headers=admin_headers)
    assert r.status_code == 200
    d = r.json()
    assert "version" in d
    for section in ("thresholds", "detection_layers", "llm", "rate_limit"):
        assert section in d
        assert d[section]["source"] in ("database", "environment")
    assert "block" in d["thresholds"]
    assert "sanitize" in d["thresholds"]
