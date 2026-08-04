# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
from services.time import to_iso_z
import time
import uuid
import hashlib
from fastapi import APIRouter, BackgroundTasks, Request, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.schemas.request import AIRequestSchema
from api.v1.dependencies.auth import get_current_principal
from api.v1.dependencies.scope import get_scoped_audit_record
from api.v1.dependencies.db import get_db
from domain.entities.principal import Principal
from db.repositories.audit import AuditRepository
from config.settings import get_settings
from domain.enums import DecisionType, DetectionMode, ExecutionMode
from domain.value_objects.trace_id import TraceId
from domain.entities.request import (
    IncomingRequest, RequestMetadata,
    RequestContext, RequestOptions
)
from errors.exceptions import NotFoundError, DebugForbiddenError
from domain.value_objects.severity import compute_severity
from services.gateway.service import GatewayService
from services.webhooks.emitter import emit_from_audit_background

router   = APIRouter()
_gateway = GatewayService()


def _mode_str(value) -> str:
    """Extract clean string from enum or string -- always returns lowercase."""
    return str(value).split(".")[-1].lower()


def _build_response(
    decision,
    debug: bool = False,
    block_threshold: float | None = None,
    sanitize_threshold: float | None = None,
) -> dict:
    response = {
        "trace_id":              str(decision.trace_id),
        "decision":              decision.decision.value,
        "decision_version":      "v1.0",
        "risk_score":            decision.risk_score.value,
        "primary_reason":        decision.primary_reason,
        "confidence":            decision.confidence,
        "confidence_band":       decision.confidence_band,
        "threats":               [t.value for t in decision.threats],
        # Only true when the input text was actually rewritten (PII redacted).
        # A SANITIZE decision from the detection tier with no PII leaves the
        # text unchanged; sanitization_applied stays false in that case.
        "sanitization_applied":  decision.sanitized_input is not None,
        "processing": {
            "latency_ms":     round(decision.latency_ms, 2),
            "llm_invoked":    decision.llm_invoked,
            "detection_mode": decision.detection_mode.value if hasattr(decision.detection_mode, "value") else decision.detection_mode,
            "execution_mode": decision.execution_mode.value if hasattr(decision.execution_mode, "value") else decision.execution_mode,
        },
    }

    if decision.sanitized_input is not None:
        response["sanitized_input"] = decision.sanitized_input

    if decision.output is not None:
        response["output"] = decision.output

    # v1.7.0 Security Assessment: an always-present, self-contained structured
    # verdict -- the decision, reasons, threats, and confidence, plus per-layer
    # contributions from the FULL layer bag (not just the five fixed keys). This
    # is the object agents and the MCP tool consume; the flat fields above stay
    # for back-compat, and the debug block below is unchanged.
    assessment = {
        "decision":        decision.decision.value,
        "risk_score":      decision.risk_score.value,
        "risk_level":      decision.risk_level.value,
        "primary_reason":  decision.primary_reason,
        "confidence":      decision.confidence,
        "confidence_band": decision.confidence_band,
        "threats":         [t.value for t in decision.threats],
        "layers":          [],
    }

    if decision.layer_scores:
        # F-6: fetch settings only if the caller-supplied thresholds are missing
        # (they normally aren't). Thresholds classify each layer's contribution
        # for both the assessment and the debug block.
        if block_threshold is None or sanitize_threshold is None:
            _fallback = get_settings()
            _bt = block_threshold    if block_threshold    is not None else _fallback.block_threshold
            _st = sanitize_threshold if sanitize_threshold is not None else _fallback.sanitize_threshold
        else:
            _bt = block_threshold
            _st = sanitize_threshold

        def layer_decision(score: float) -> str:
            if score >= _bt:
                return DecisionType.BLOCK.value
            if score >= _st:
                return DecisionType.SANITIZE.value
            return DecisionType.ALLOW.value

        assessment["layers"] = [
            {"name": name, "score": score, "decision": layer_decision(score)}
            for name, score in decision.layer_scores.as_dict().items()
        ]

        if debug:
            response["debug"] = {
                "rule_score": decision.layer_scores.rule_score,
                "ml_score":   decision.layer_scores.ml_score,
                "llm_score":  decision.layer_scores.llm_score,
                "pii_score":  decision.layer_scores.pii_score,
                "layer_decisions": {
                    "rule": layer_decision(decision.layer_scores.rule_score),
                    "ml":   layer_decision(decision.layer_scores.ml_score),
                    "llm":  layer_decision(decision.layer_scores.llm_score),
                }
            }

    response["assessment"] = assessment
    return response


@router.post("/request", response_model=None)
async def ai_request(
    body:            AIRequestSchema,
    request:         Request,
    background_tasks: BackgroundTasks,
    db:              AsyncSession = Depends(get_db),
    _principal:      Principal    = Depends(get_current_principal),
):
    """
    Main AI security scan endpoint.

    Processing order:
      1. Debug mode guard - only admin keys may request debug output.
      2. Debug rate limit - separate 10/min bucket prevents model fingerprinting.
      3. Trial key restrictions - input size cap and proxy mode blocked.
      4. Trial rate limit - stricter per-minute limit applied on top of global middleware limit.
      5. Semantic cache lookup - returns cached result on hit, skips pipeline.
      6. Policy resolution - resolves effective thresholds and detection layers for the
         request's tenant/dept/app scope.
      7. Detection pipeline - runs via GatewayService (rule, ML, LLM layers as configured).
      8. Audit log write - persists full decision record to audit_logs.
      9. Metrics recording - non-blocking; errors are swallowed.
     10. Semantic cache write - caches successful responses for future identical inputs.

    Auth: any valid principal (API key).
    """
    if body.options.debug and not getattr(request.state, "is_admin", False):
        raise DebugForbiddenError()

    # F-6: single per-call snapshot of settings for this request. Reading
    # config once at handler entry keeps the request internally consistent
    # (all fields read from the same version) while still honoring the
    # per-call invariant so key rotation and test overrides take effect.
    _settings = get_settings()

    # Debug rate limit - separate bucket, tighter than global limit.
    # Prevents model fingerprinting: an attacker with a stolen admin key
    # cannot probe 60 inputs/min to calibrate below-threshold payloads.
    # Fails open if Redis unavailable - consistent with other rate limit checks.
    if body.options.debug:
        try:
            from cache.rate_limit_store import is_rate_limited
            key_id   = getattr(request.state, "key_id", None)
            debug_id = f"debug:key:{key_id or 'admin'}"
            is_limited, _, _ = await is_rate_limited(
                debug_id,
                limit=_settings.debug_rate_limit_per_minute,
            )
            if is_limited:
                from errors.exceptions import RateLimitError
                raise RateLimitError()
        except RateLimitError:
            raise
        except Exception:
            pass  # Fail open if Redis unavailable

    # Trial key restrictions - enforced after auth, key_type is available here
    key_type = getattr(request.state, "key_type", "live")
    if key_type == "trial":
        # Input size cap - stricter than the global max_input_chars limit
        if len(body.input) > _settings.trial_max_input_chars:
            from errors.exceptions import ValidationError
            raise ValidationError(
                f"Trial keys are limited to {_settings.trial_max_input_chars} characters. "
                f"Upgrade to a live key for full input limits."
            )
        # Proxy mode not available for trial keys
        from domain.enums import ExecutionMode as _ExecMode
        if _mode_str(body.execution_mode) == "proxy" or body.execution_mode == _ExecMode.PROXY:
            from errors.exceptions import ForbiddenError
            raise ForbiddenError("Proxy mode is not available for trial keys.")

        # Trial rate limit - enforced here since rate_limit middleware runs before auth
        # Global rate limit (60/min) is already enforced by middleware
        # We enforce the stricter trial limit (10/min) here using the same Redis store
        try:
            from cache.rate_limit_store import is_rate_limited
            key_id = getattr(request.state, "key_id", None)
            if key_id:
                trial_id = f"trial:key:{key_id}"
                is_limited, remaining, reset_at = await is_rate_limited(
                    trial_id,
                    limit=_settings.trial_rate_limit_per_minute,
                )
                if is_limited:
                    from errors.exceptions import RateLimitError
                    raise RateLimitError()
        except RateLimitError:
            raise
        except Exception:
            pass  # Fail open if Redis unavailable

    det_mode_str = _mode_str(body.detection_mode)
    exe_mode_str = _mode_str(body.execution_mode)

    from cache.semantic_cache import get_cached_result, set_cached_result
    from observability.metrics import CACHE_HITS, CACHE_MISSES
    _tenant_id = getattr(request.state, "tenant_id", None) or "global"
    cached = await get_cached_result(body.input, det_mode_str, exe_mode_str, _tenant_id)
    if cached:
        CACHE_HITS.inc()
        # Overwrite the cached body's trace_id with the current request's so the
        # response body matches the X-Trace-Id header stamped by TraceMiddleware.
        # Without this, the cached trace_id belongs to the original requester and
        # trace correlation breaks for cache-hit responses.
        _current_trace_id = getattr(request.state, "trace_id", None)
        if _current_trace_id:
            cached = {**cached, "trace_id": _current_trace_id}
        return JSONResponse(content=cached)
    CACHE_MISSES.inc()

    incoming = IncomingRequest(
        input          = body.input,
        detection_mode = DetectionMode(det_mode_str),
        execution_mode = ExecutionMode(exe_mode_str),
        model          = body.model,
        metadata       = RequestMetadata(
            tenant_id = getattr(request.state, "tenant_id", None),
            source    = body.metadata.source  if body.metadata else None,
            user_id   = body.metadata.user_id if body.metadata else None,
        ),
        context        = RequestContext(
            user_role   = body.context.user_role if body.context else None,
            sensitivity = body.context.sensitivity if body.context else None,
        ),
        options        = RequestOptions(
            stream = body.options.stream if body.options else False,
            debug  = body.options.debug if body.options else False,
        ),
    )

    from services.policy_resolver import resolve_policy
    policy, policy_source = await resolve_policy(
        db        = db,
        tenant_id = getattr(request.state, "tenant_id", None),
        dept_id   = getattr(request.state, "dept_id",   None),
        app_id    = getattr(request.state, "app_id",    None),
    )

    # Per-app rate limit - enforced when app_id is known and rate_limit_override is set.
    # Uses a separate per-app bucket so the global middleware bucket is unaffected.
    # Fails open if Redis is unavailable - consistent with all other rate limit checks.
    _app_id = getattr(request.state, "app_id", None)
    if _app_id:
        _app_rate_limit = policy.get("rate_limit", {}).get("per_minute")
        if _app_rate_limit is not None:
            try:
                from cache.rate_limit_store import is_rate_limited
                _app_limited, _, _ = await is_rate_limited(
                    f"app:{_app_id}",
                    limit=_app_rate_limit,
                )
                if _app_limited:
                    from errors.exceptions import RateLimitError
                    raise RateLimitError()
            except RateLimitError:
                raise
            except Exception:
                pass

    block_threshold    = policy["thresholds"]["block"]
    sanitize_threshold = policy["thresholds"]["sanitize"]
    rule_enabled       = policy["detection"]["rule_enabled"]
    ml_enabled         = policy["detection"]["ml_enabled"]
    llm_enabled        = policy["detection"]["llm_enabled"]
    llm_settings       = policy["llm"]

    if body.execution_mode == ExecutionMode.PROXY and not llm_enabled:
        from errors.exceptions import WrapSecError
        raise WrapSecError(
            code        = "VALIDATION_ERROR",
            message     = "Proxy mode requires LLM layer to be enabled",
            status_code = 422,
        )

    pii_policy             = policy.get("guardrails", {}).get("pii", {})
    pii_block_threshold    = pii_policy.get("block_threshold",    None)
    pii_sanitize_threshold = pii_policy.get("sanitize_threshold", None)

    toxicity_policy             = policy.get("guardrails", {}).get("toxicity", {})
    toxicity_block_threshold    = toxicity_policy.get("block_threshold",    None)
    toxicity_sanitize_threshold = toxicity_policy.get("sanitize_threshold", None)

    result = await _gateway.process(
        incoming,
        block_threshold,
        sanitize_threshold,
        pii_block_threshold,
        pii_sanitize_threshold,
        toxicity_block_threshold,
        toxicity_sanitize_threshold,
        rule_enabled,
        ml_enabled,
        llm_enabled,
        llm_settings,
    )

    detection_scores = {}
    guardrail_scores = {}
    if result.decision.layer_scores:
        detection_scores = {
            "rule": result.decision.layer_scores.rule_score,
            "ml":   result.decision.layer_scores.ml_score,
            "llm":  result.decision.layer_scores.llm_score,
        }
        guardrail_scores = {
            "pii": result.decision.layer_scores.pii_score,
        }
        if result.decision.layer_scores.toxicity_score > 0.0:
            guardrail_scores["toxicity"] = result.decision.layer_scores.toxicity_score

    source = (
        (body.metadata.source if body.metadata and body.metadata.source else None)
        or getattr(request.state, "key_name", None)
        or "unknown"
    )

    # Single audit dict shared between the DB write and the webhook emit,
    # so the wire payload is a faithful subset of the row that was persisted.
    audit_data = {
        "trace_id":              str(incoming.trace_id),
        "decision":              result.decision.decision.value,
        "risk_score":            result.decision.risk_score.value,
        "threats":               [t.value for t in result.decision.threats],
        "input_hash":            result.audit_log.input_hash,
        "detection_mode":        det_mode_str,
        "execution_mode":        exe_mode_str,
        "llm_invoked":           result.decision.llm_invoked,
        "latency_ms":            round(result.decision.latency_ms, 2),
        "detection_scores":      detection_scores,
        "guardrail_scores":      guardrail_scores,
        "tenant_id":             getattr(request.state, "tenant_id", None),
        "source":                source,
        "user_id":               body.metadata.user_id if body.metadata else None,
        "key_id":                getattr(request.state, "key_id",     None),
        "ip_address":            getattr(request.state, "ip_address",  None),
        "user_agent":            getattr(request.state, "user_agent",  None),
        "attribution_verified":  False,
        "app_id":                getattr(request.state, "app_id",     None),
        "dept_id":               getattr(request.state, "dept_id",    None),
        "policy_source":         policy_source,
        "primary_reason":        result.decision.primary_reason,
        "confidence":            result.decision.confidence,
        "confidence_band":       result.decision.confidence_band,
        "input_length":          len(body.input),
        "session_id":            body.session_id,
        "turn_index":            body.turn_index,
        "run_id":                body.run_id,
        "input_source":          body.input_source,
        "proxy_interaction_id":  None,
        "severity":              compute_severity(
            decision       = result.decision.decision.value,
            risk_score     = result.decision.risk_score.value,
            primary_reason = result.decision.primary_reason,
        ),
    }

    repo = AuditRepository(db)
    await repo.create(audit_data)

    # Schedule webhook emit to run AFTER the response body is on the wire.
    # emit_from_audit_background owns its session + swallows exceptions, so
    # the scan response is immune to webhook subsystem latency and failures.
    background_tasks.add_task(emit_from_audit_background, audit_data)

    try:
        from observability.metrics import record_request
        record_request(
            decision       = result.decision.decision.value,
            detection_mode = det_mode_str,
            execution_mode = exe_mode_str,
            latency_ms     = result.decision.latency_ms,
            threats        = [t.value for t in result.decision.threats],
            layer_scores   = {
                "rule": result.decision.layer_scores.rule_score,
                "ml":   result.decision.layer_scores.ml_score,
                "llm":  result.decision.layer_scores.llm_score,
            } if result.decision.layer_scores else None,
            primary_reason = result.decision.primary_reason,
            key_type       = getattr(request.state, "key_type", "live"),
        )
    except Exception:
        pass  # Metrics must never break scan responses

    response = _build_response(
        result.decision,
        debug               = body.options.debug and getattr(request.state, "is_admin", False),
        block_threshold     = block_threshold,
        sanitize_threshold  = sanitize_threshold,
    )

    # Cache the non-debug shape only. If we cached the debug-included body, a
    # subsequent non-admin request for the same input would hit the cache and
    # receive per-layer detector scores meant for admins only. Building a
    # separate cache-safe copy keeps the on-hit path uniformly non-debug.
    cache_body = {k: v for k, v in response.items() if k != "debug"}
    await set_cached_result(body.input, det_mode_str, exe_mode_str, _tenant_id, cache_body)

    return JSONResponse(content=response)


@router.get("/requests/{trace_id}")
async def get_request(
    trace_id:   str,
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Returns the full audit record for a single request by trace_id.
    Admin keys use an unscoped lookup; all other keys are scoped to their dept_id.
    For proxy requests, the response is enriched with the full proxy_interactions record
    including provider response, output decision, and execution status.
    404 if the record does not exist or is out of scope.
    """
    repo   = AuditRepository(db)
    record = await get_scoped_audit_record(repo, trace_id, request)

    if not record:
        raise NotFoundError("request", trace_id)

    # Enrich with human-readable names
    dept_name = None
    app_name  = None
    if record.dept_id:
        try:
            from db.repositories.department import DepartmentRepository
            dept_repo = DepartmentRepository(db)
            dept      = await dept_repo.get_by_id(uuid.UUID(record.dept_id))
            dept_name = dept.name if dept else None
        except Exception:
            pass
    if record.app_id:
        try:
            from db.repositories.application import ApplicationRepository
            app_repo = ApplicationRepository(db)
            app      = await app_repo.get_by_id(uuid.UUID(record.app_id))
            app_name = app.name if app else None
        except Exception:
            pass

    # Build base response
    response = {
        "trace_id":       record.trace_id,
        "timestamp":      to_iso_z(record.created_at),
        "execution_mode": record.execution_mode,
        "is_proxy":       record.execution_mode == "proxy",
        "severity":       record.severity or compute_severity(
            decision       = record.decision,
            risk_score     = record.risk_score or 0.0,
            primary_reason = record.primary_reason,
        ),
        "attribution": {
            "tenant_id":            record.tenant_id,
            "dept_id":              record.dept_id,
            "dept_name":            dept_name,
            "app_id":               record.app_id,
            "app_name":             app_name,
            "source":               record.source,
            "user_id":              record.user_id,
            "key_id":               record.key_id,
            "ip_address":           record.ip_address,
            "user_agent":           record.user_agent,
            "attribution_verified": record.attribution_verified,
        },
        "decision":        record.decision,
        "risk_score":      record.risk_score,
        "primary_reason":  record.primary_reason,
        "confidence":      record.confidence,
        "confidence_band": record.confidence_band,
        "threats":         record.threats or [],
        "input_hash":        record.input_hash,
        "input_length":      record.input_length or 0,
        "detection_scores":  record.detection_scores or {},
        "guardrail_scores":  record.guardrail_scores or {},
        "processing": {
            "latency_ms":     record.latency_ms,
            # For scan_only: detection pipeline time only
            # For proxy:     total end-to-end time (detection + provider + overhead)
            "llm_invoked":    record.llm_invoked,
            "detection_mode": record.detection_mode,
            "execution_mode": record.execution_mode,
            "policy_source":  record.policy_source,
        },
    }

    # If proxy request, JOIN proxy_interactions for extended lifecycle data
    if record.proxy_interaction_id:
        try:
            from db.models import ProxyInteractionModel
            pi_result = await db.execute(
                select(ProxyInteractionModel).where(
                    ProxyInteractionModel.id == record.proxy_interaction_id
                )
            )
            pi = pi_result.scalar_one_or_none()
            if pi:
                response["proxy"] = {
                    "provider":              pi.provider,
                    "model":                 pi.model,
                    "provider_latency_ms":   pi.provider_latency_ms,
                    "total_latency_ms":      pi.total_latency_ms,
                    "execution_status":      pi.execution_status,
                    "input_primary_reason":  pi.input_primary_reason,
                    "input_confidence":      pi.input_confidence,
                    "input_threats":         pi.input_threats or [],
                    "input_attack_type":     pi.input_attack_type,
                    "input_raw":             pi.input_raw,
                    "input_sanitized":       pi.input_sanitized,
                    "output_decision":       pi.output_decision,
                    "output_primary_reason": pi.output_primary_reason,
                    "output_confidence":     pi.output_confidence,
                    "output_threats":        pi.output_threats or [],
                    "output_raw":            pi.output_raw,
                    "output_sanitized":      pi.output_sanitized,
                    "behavior_flag":         pi.behavior_flag,
                    "output_flags":          pi.output_flags,
                }
        except Exception as exc:
            logging.getLogger("wrapsec.ai").error(
                "Failed to join proxy_interactions for trace_id=%s: %s", trace_id, exc
            )

    return JSONResponse(content=response)