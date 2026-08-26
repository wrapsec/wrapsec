# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal
from api.v1.dependencies.db import get_db
from api.v1.schemas.response import (
    ErrorEnvelope,
    HealthConfigResponse,
    HealthResponse,
    LivenessResponse,
    ReadinessResponse,
)
from config.settings import get_settings
from domain.entities.principal import Principal

router = APIRouter()

# `/health`, `/health/live` and `/health/ready` are unauthenticated, so they have
# no 401 to document. `/health/config` admits any authenticated caller and has no
# parameters to validate, so 401 is its only reachable failure.
_CONFIG_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Missing or invalid credentials."},
}


@router.get(
    "/health",
    response_model               = HealthResponse,
    response_model_exclude_unset = True,
)
async def health():
    return {
        "status":  "ok",
        "version": get_settings().app_version,
    }


@router.get(
    "/health/ready",
    response_model               = ReadinessResponse,
    response_model_exclude_unset = True,
    responses = {
        200: {"model": ReadinessResponse, "description": "Every required component is up. The body may still read `degraded` when an optional one is absent."},
        503: {"model": ReadinessResponse, "description": "A required component is down; the instance cannot serve. Same body shape."},
    },
)
async def health_ready(response: Response):
    """
    Readiness check. Used by container orchestrators to decide whether to route
    traffic, so the STATUS CODE is the contract and the body is the detail.

    200 -- every REQUIRED component is up: database, Redis, and the Tier-1 ML
           model. The body may still read "degraded", which means an OPTIONAL
           component is absent: the Tier-2 transformer is not installed in the
           default build, and running without it is the documented degraded
           mode rather than a fault.
    503 -- a required component is down. The instance cannot serve: a request
           that runs the ML layer with no Tier-1 model is refused fail-closed
           with SYSTEM_ERROR, so routing to it produces errors, not weaker
           scoring.
    """
    from cache.redis_client import ping as redis_ping
    from db.session import AsyncSessionFactory

    # Database ping
    db_ok = False
    try:
        async with AsyncSessionFactory() as session:
            await session.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    # Redis ping
    redis_ok = await redis_ping()

    # Per-detector status -- each tier reported separately.
    #
    # The two tiers are NOT equivalent when degraded. Tier 2 is optional by
    # build: absent, it reports degraded and traffic is served on Tier 1.
    # Tier 1 is required: absent, MLDetector.detect returns a detector
    # FAILURE and the fail-closed override refuses every request that runs
    # the ML layer. A degraded tfidf_detector therefore means the deployment
    # is refusing traffic, not merely scoring it with less signal.
    tfidf_status       = "unavailable"
    transformer_status = "unavailable"
    try:
        from engine.detection.ml_detector import MLDetector
        from engine.detection.transformer_detector import TransformerDetector
        tfidf_status       = "healthy" if MLDetector.is_model_loaded()       else "degraded"
        transformer_status = "healthy" if TransformerDetector.is_model_loaded() else "degraded"
    except Exception:
        pass  # Detector status probe is best-effort; report 'unavailable' on error.

    checks = {
        "database":             "ok"      if db_ok    else "unavailable",
        "redis":                "ok"      if redis_ok else "unavailable",
        "tfidf_detector":       tfidf_status,
        "transformer_detector": transformer_status,
    }
    all_ok = all(v in ("ok", "healthy") for v in checks.values())

    # Which checks decide the STATUS CODE, as opposed to the body.
    #
    # transformer_detector is deliberately absent: Tier 2 is optional by build
    # and reports degraded on every default deployment, so keying the code on
    # every check would fail readiness for a correctly-installed gateway.
    #
    # tfidf_detector is present because Tier 1 is required. When its model has
    # not loaded, MLDetector.detect returns a detector FAILURE and the
    # fail-closed override refuses every request that runs the ML layer -- the
    # instance is serving errors, not serving degraded.
    _REQUIRED = ("database", "redis", "tfidf_detector")
    required_ok = all(checks[name] in ("ok", "healthy") for name in _REQUIRED)

    body = {
        "status": "ready" if all_ok else "degraded",
        "checks": checks,
    }

    # 200 with a degraded body means "serving, with less signal" -- the Tier-2
    # case. 503 means "not serving": a readiness probe reads the status code, so
    # returning 200 here kept an orchestrator routing to an instance that
    # refused every request with SYSTEM_ERROR, and never restarted it. The body
    # is unchanged in both cases; the code is what the orchestrator acts on.
    # The code is set on the injected Response rather than by constructing one,
    # so the BODY still passes through the response model. Returning a
    # JSONResponse here would carry the same bytes and the same code while
    # bypassing validation and filtering entirely -- which is exactly the
    # advertised-but-unenforced shape this phase exists to remove.
    response.status_code = 200 if required_ok else 503
    return body


@router.get(
    "/health/live",
    response_model               = LivenessResponse,
    response_model_exclude_unset = True,
)
async def health_live():
    return {"status": "alive"}


@router.get(
    "/health/config",
    response_model               = HealthConfigResponse,
    # Load-bearing here, not merely conventional: a caller without
    # `settings:read` receives each section reduced to its `source` marker, and
    # the withheld values must be ABSENT. exclude_none would drop legitimate
    # nulls elsewhere; exclude_unset drops exactly the keys the handler did not
    # set, which is the restriction itself.
    response_model_exclude_unset = True,
    responses                    = _CONFIG_ERRORS,
)
async def health_config(
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    The configuration currently in force, for deployment verification.

    The route admits every authenticated caller, but the BODY varies by
    permission. Values here duplicate what `GET /v1/settings` returns behind
    `settings:read` with trial keys refused -- thresholds and layer status are
    the calibration data that restriction exists to withhold, since they tell a
    caller exactly how far under a limit a payload has to sit. Served from an
    endpoint with no such check, the restriction meant nothing: the same trial
    key or VIEWER simply read it here.

    Gating the whole route instead would have broken deployment verification
    for the callers most likely to need it, so the split is per field:

      settings:read (ADMIN, DEVELOPER, AUDITOR; not trial)
          everything, unchanged.
      everyone else authenticated (VIEWER, trial keys)
          `version`, plus each section reduced to its `source` marker. That is
          enough to confirm which build is running and whether configuration is
          database-backed or environment-default -- the verification purpose --
          without disclosing a single threshold or layer state.

    Never exposes API keys or secrets to any caller.
    """
    from api.v1.dependencies.auth import holds_permission

    # The identical predicate `/v1/settings` enforces, asked rather than
    # enforced, so the two cannot drift into disagreeing about who may read
    # calibration data.
    may_read_settings = holds_permission(request, "settings:read")
    from api.v1.endpoints.settings import _resolve_tenant
    from db.repositories.settings import TenantSettingsRepository

    _settings         = get_settings()
    _tid              = await _resolve_tenant(db, _principal)
    repo              = TenantSettingsRepository(db)
    stored_thresholds = await repo.get(_tid, "policy_thresholds") or {}
    stored_layers     = await repo.get(_tid, "detection_layers")  or {}
    stored_llm        = await repo.get(_tid, "llm_settings")      or {}
    stored_rate_limit = await repo.get(_tid, "rate_limit")        or {}

    # `version` is unrestricted: unauthenticated `GET /health` already returns
    # it, so withholding it here would protect nothing. Every other section is
    # reduced to its origin marker, which says whether configuration was
    # customised without saying what it was set to.
    body: dict = {
        "version": _settings.app_version,
        "thresholds":       {"source": "database" if stored_thresholds else "environment"},
        "detection_layers": {"source": "database" if stored_layers     else "environment"},
        "llm":              {"source": "database" if stored_llm        else "environment"},
        "rate_limit":       {"source": "database" if stored_rate_limit else "environment"},
    }

    if not may_read_settings:
        return body

    body["thresholds"].update({
        "block":    stored_thresholds.get("block_threshold",    _settings.block_threshold),
        "sanitize": stored_thresholds.get("sanitize_threshold", _settings.sanitize_threshold),
    })
    body["detection_layers"].update({
        "rule": stored_layers.get("rule_enabled", True),
        "ml":   stored_layers.get("ml_enabled",   True),
        "llm":  stored_layers.get("llm_enabled",  True),
    })
    body["llm"].update({
        "provider":    stored_llm.get("provider",    _settings.llm_provider),
        "model":       stored_llm.get("model",       _settings.llm_model),
        "llm_trigger": stored_llm.get("llm_trigger", _settings.llm_trigger_threshold),
        "timeout":     stored_llm.get("timeout",     _settings.llm_timeout),
    })
    body["rate_limit"]["per_minute"] = stored_rate_limit.get(
        "per_minute", _settings.rate_limit_per_minute
    )
    return body