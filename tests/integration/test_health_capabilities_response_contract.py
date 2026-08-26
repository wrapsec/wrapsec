# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The health and capabilities response models are applied by the runtime.

These five bodies are built from LITERALS plus a couple of computed values, so
the undeclared-field injection used for the scan and audit families has no seam
here -- there is no shared formatter to wrap. The equivalent proof is a TYPE
violation: a value is forced to the wrong type at its source, and the model must
refuse to serve it. A `JSONResponse` would hand the caller the bad value
untouched, so each of these tests fails if the success return is reverted, which
is the property the mutation check requires.

Coverage per route, stated exactly rather than implied:

  * `/health`          -- version forced to an int at `get_settings`;
  * `/health/config`   -- a threshold forced to a string, plus the
                          caller-dependent ABSENCE which is this family's real
                          contract risk;
  * `/v1/capabilities` -- a capability list containing a non-string;
  * `/health/ready`    -- no injectable seam at all (four locals and two literal
                          strings), so it is covered by both states end to end
                          and by the source-level bypass test in
                          `tests/unit/test_response_model_enforcement.py`;
  * `/health/live`     -- returns a two-key literal with no dependency. Nothing
                          can be injected, and the source-level test is the only
                          thing that catches a reverted return. Said plainly
                          instead of dressing a shape assertion up as
                          enforcement.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.exceptions import ResponseValidationError

# ── GET /health ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_will_not_serve_a_non_string_version(client, monkeypatch):
    from api.v1.endpoints import health

    monkeypatch.setattr(health, "get_settings", lambda: SimpleNamespace(app_version=12345))

    try:
        r = await client.get("/health")
    except ResponseValidationError as rejected:
        assert "version" in str(rejected)
        return

    assert r.status_code != 200 or "12345" not in r.text, (
        "a version that violates the declared type was served, so the response "
        "model is not applied to /health"
    )


@pytest.mark.asyncio
async def test_health_serves_exactly_the_declared_fields(client):
    from api.v1.schemas.response import HealthResponse

    r = await client.get("/health")

    assert r.status_code == 200, r.text
    assert set(r.json()) == set(HealthResponse.model_fields)
    assert r.json()["status"] == "ok"


# ── GET /health/live ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_live_is_unchanged(client):
    """No enforcement seam exists here; this pins the body so the endpoint keeps
    answering what a liveness probe expects."""
    from api.v1.schemas.response import LivenessResponse

    r = await client.get("/health/live")

    assert r.status_code == 200, r.text
    assert r.json() == {"status": "alive"}
    assert set(r.json()) == set(LivenessResponse.model_fields)


# ── GET /health/ready, both states ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_ready_is_200_with_the_declared_shape(client):
    from api.v1.schemas.response import HealthChecks, ReadinessResponse

    r = await client.get("/health/ready")

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == set(ReadinessResponse.model_fields)
    assert set(body["checks"]) == set(HealthChecks.model_fields)
    assert body["status"] in ("ready", "degraded")


@pytest.mark.asyncio
async def test_ready_is_503_when_a_required_component_is_down(client):
    """The status code is the contract an orchestrator acts on. The body keeps
    the same shape; only the code changes."""
    from api.v1.schemas.response import HealthChecks, ReadinessResponse

    with patch("cache.redis_client.ping", AsyncMock(return_value=False)):
        r = await client.get("/health/ready")

    assert r.status_code == 503, (
        f"a required component was down and readiness still returned {r.status_code}"
    )
    body = r.json()
    assert body["status"] == "degraded"
    assert body["checks"]["redis"] == "unavailable"
    assert set(body) == set(ReadinessResponse.model_fields), (
        "the degraded body lost or gained a field relative to the ready body"
    )
    assert set(body["checks"]) == set(HealthChecks.model_fields)


# ── GET /health/config ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_config_withholds_values_by_absence_not_null(client, scored_key_pair):
    """The family's real contract risk. A caller without `settings:read` receives
    each section reduced to its `source` marker -- the numbers must be ABSENT,
    since a null still confirms a threshold exists and is being withheld."""
    live, trial = scored_key_pair

    authorized = await client.get("/health/config", headers=live)
    restricted = await client.get("/health/config", headers=trial)
    assert authorized.status_code == 200 and restricted.status_code == 200

    a, r = authorized.json(), restricted.json()
    assert set(a) == set(r), "the top-level key set must not vary by caller"

    for field in ("block", "sanitize"):
        assert field in a["thresholds"], f"the authorized caller lost {field}"
        assert field not in r["thresholds"], (
            f"{field} reached a caller without settings:read"
        )
    assert set(r["thresholds"]) == {"source"}
    assert set(r["detection_layers"]) == {"source"}
    assert set(r["llm"]) == {"source"}
    assert set(r["rate_limit"]) == {"source"}
    for section in ("thresholds", "detection_layers", "llm", "rate_limit"):
        assert r[section]["source"] in ("database", "environment")


@pytest.mark.asyncio
async def test_config_will_not_serve_a_wrong_typed_threshold(client, scored_key_pair, monkeypatch):
    """Enforcement, through the one value on this route that comes from outside
    the handler."""
    from api.v1.endpoints import health

    live, _ = scored_key_pair
    real = health.get_settings()

    def _bad():
        return SimpleNamespace(
            app_version=real.app_version, block_threshold="not-a-number",
            sanitize_threshold=real.sanitize_threshold, llm_provider=real.llm_provider,
            llm_model=real.llm_model, llm_trigger_threshold=real.llm_trigger_threshold,
            llm_timeout=real.llm_timeout, rate_limit_per_minute=real.rate_limit_per_minute,
        )

    monkeypatch.setattr(health, "get_settings", _bad)

    try:
        r = await client.get("/health/config", headers=live)
    except ResponseValidationError as rejected:
        assert "block" in str(rejected)
        return

    assert r.status_code != 200 or "not-a-number" not in r.text, (
        "a threshold that violates the declared type was served, so the response "
        "model is not applied to /health/config"
    )


# ── GET /v1/capabilities ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_capabilities_will_not_serve_a_non_string_capability(client, admin_headers, monkeypatch):
    from api.v1.endpoints import capabilities

    monkeypatch.setattr(capabilities, "effective_capabilities", lambda: [{"not": "a string"}])

    try:
        r = await client.get("/v1/capabilities", headers=admin_headers)
    except ResponseValidationError as rejected:
        assert "capabilities" in str(rejected)
        return

    # Checked structurally, not by substring: the serialized form of the bad
    # entry is `{"not": "a string"}`, which a naive substring search for
    # "not a string" does not match -- the assertion passed while the value was
    # being served.
    assert r.status_code != 200 or all(
        isinstance(c, str) for c in r.json()["capabilities"]
    ), "a capability list violating the declared type was served"


@pytest.mark.asyncio
async def test_capabilities_reports_the_oss_build(client, admin_headers):
    """Process-global and informational. The OSS build registers nothing, so the
    empty list and `oss` are the contract -- an empty array, never a null."""
    from api.v1.schemas.response import CapabilitiesResponse

    r = await client.get("/v1/capabilities", headers=admin_headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == set(CapabilitiesResponse.model_fields)
    assert body["capabilities"] == [] and body["edition"] == "oss"


@pytest.mark.asyncio
async def test_config_restricted_branch_serves_only_the_declared_fields(client, scored_key_pair):
    """The restricted early return is a SECOND success path on this route, and
    it produces a body a `JSONResponse` would serve identically -- so no
    undeclared-field or type probe can distinguish the two there. What can be
    asserted is that the reduced body is exactly the declared sections with only
    their `source`, which is the contract that path exists to keep."""
    from api.v1.schemas.response import HealthConfigResponse

    _, trial = scored_key_pair

    r = await client.get("/health/config", headers=trial)

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == set(HealthConfigResponse.model_fields)
    assert isinstance(body["version"], str)
    for section in ("thresholds", "detection_layers", "llm", "rate_limit"):
        assert set(body[section]) == {"source"}
