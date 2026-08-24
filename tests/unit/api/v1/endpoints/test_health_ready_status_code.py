# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
`/health/ready` status-code contract.

A readiness probe reads the status code, not the body. The endpoint returned 200
with `"status": "degraded"` whenever anything was degraded -- including a
Tier-1 model that had not loaded, which makes every request that runs the ML
layer refuse fail-closed. An orchestrator kept routing to that instance and
never restarted it, so the outage self-healed nowhere.

The two tiers are not equivalent and the tests below pin the difference:

  Tier 2 absent  -> optional by build; body degraded, code 200 (still serving)
  Tier 1 absent  -> required;          body degraded, code 503 (not serving)

The Tier-2 case is the one that makes this dangerous to get wrong in the other
direction: it is degraded on every default deployment, so keying the code on
"anything degraded" would fail readiness for a correctly-installed gateway.
"""

from unittest.mock import AsyncMock, patch

import pytest

from api.v1.endpoints.health import health_ready


async def _ready(*, db_ok=True, redis_ok=True, tfidf=True, transformer=True):
    """Drive the endpoint with each dependency's health forced."""
    class _Session:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def execute(self, *a, **kw):
            if not db_ok:
                raise RuntimeError("database down")

    with patch("db.session.AsyncSessionFactory", _Session), \
         patch("cache.redis_client.ping", AsyncMock(return_value=redis_ok)), \
         patch("engine.detection.ml_detector.MLDetector.is_model_loaded",
               return_value=tfidf), \
         patch("engine.detection.transformer_detector.TransformerDetector.is_model_loaded",
               return_value=transformer):
        return await health_ready()


def _body(response) -> dict:
    import json
    return json.loads(response.body)


# ── everything healthy ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_all_healthy_is_200_and_ready():
    response = await _ready()
    assert response.status_code == 200
    assert _body(response)["status"] == "ready"


# ── optional tier: must NOT fail readiness ───────────────────────────────────

@pytest.mark.asyncio
async def test_absent_tier_2_is_degraded_but_still_200():
    """
    The default build ships without the transformer. If this returns 503 every
    stock deployment fails its readiness probe and is removed from rotation --
    an outage caused by the fix rather than by the fault.
    """
    response = await _ready(transformer=False)
    assert response.status_code == 200, (
        "an absent optional Tier 2 must not fail readiness -- this is the "
        "default build"
    )
    body = _body(response)
    assert body["status"] == "degraded"
    assert body["checks"]["transformer_detector"] == "degraded"
    assert body["checks"]["tfidf_detector"] == "healthy"


# ── required components: must fail readiness ─────────────────────────────────

@pytest.mark.asyncio
async def test_absent_tier_1_is_503():
    """
    With no Tier-1 model, MLDetector.detect returns a detector failure and every
    request running the ML layer is refused with SYSTEM_ERROR. The instance must
    be taken out of rotation rather than left serving errors behind a 200.
    """
    response = await _ready(tfidf=False)
    assert response.status_code == 503
    body = _body(response)
    assert body["status"] == "degraded"
    assert body["checks"]["tfidf_detector"] == "degraded"


@pytest.mark.asyncio
async def test_database_down_is_503():
    response = await _ready(db_ok=False)
    assert response.status_code == 503
    assert _body(response)["checks"]["database"] == "unavailable"


@pytest.mark.asyncio
async def test_redis_down_is_503():
    response = await _ready(redis_ok=False)
    assert response.status_code == 503
    assert _body(response)["checks"]["redis"] == "unavailable"


# ── body shape is unchanged ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_body_keeps_its_existing_shape_in_both_cases():
    """
    Only the status code was added. Anything consuming the body -- the CLI
    doctor, dashboards -- must be unaffected.
    """
    for response in (await _ready(), await _ready(tfidf=False)):
        body = _body(response)
        assert set(body) == {"status", "checks"}
        assert set(body["checks"]) == {
            "database", "redis", "tfidf_detector", "transformer_detector",
        }
