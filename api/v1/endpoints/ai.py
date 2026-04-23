import time
import hashlib
from fastapi import APIRouter, Request, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.schemas.request import AIRequestSchema
from api.v1.dependencies.db import get_db
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

router   = APIRouter()
settings = get_settings()
_gateway = GatewayService()


def _mode_str(value) -> str:
    """Extract clean string from enum or string -- always returns lowercase."""
    return str(value).split(".")[-1].lower()


def _build_response(decision, debug: bool = False) -> dict:
    response = {
        "trace_id":              str(decision.trace_id),
        "decision":              decision.decision.value,
        "decision_version":      "v1.0",
        "risk_score":            decision.risk_score.value,
        "primary_reason":        decision.primary_reason,
        "confidence":            decision.confidence,
        "confidence_band":       decision.confidence_band,
        "threats":               [t.value for t in decision.threats],
        "sanitization_applied":  decision.decision.value == "SANITIZE",
        "processing": {
            "latency_ms":     round(decision.latency_ms, 2),
            "llm_invoked":    decision.llm_invoked,
            "detection_mode": decision.detection_mode.value if hasattr(decision.detection_mode, "value") else decision.detection_mode,
            "execution_mode": decision.execution_mode.value if hasattr(decision.execution_mode, "value") else decision.execution_mode,
        },
    }

    if decision.decision.value == "SANITIZE":
        response["sanitized_input"] = decision.sanitized_input

    if decision.output is not None:
        response["output"] = decision.output

    if debug and decision.layer_scores:
        def layer_decision(score: float) -> str:
            if score >= settings.block_threshold:
                return DecisionType.BLOCK.value
            if score >= settings.sanitize_threshold:
                return DecisionType.SANITIZE.value
            return DecisionType.ALLOW.value

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

    return response


@router.post("/request", response_model=None)
async def ai_request(
    body:    AIRequestSchema,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    if body.options.debug and not getattr(request.state, "is_admin", False):
        raise DebugForbiddenError()

    # Trial key restrictions — enforced after auth, key_type is available here
    key_type = getattr(request.state, "key_type", "live")
    if key_type == "trial":
        # Input size cap — stricter than the global 8000 char limit
        if len(body.input) > settings.trial_max_input_chars:
            from errors.exceptions import ValidationError
            raise ValidationError(
                f"Trial keys are limited to {settings.trial_max_input_chars} characters. "
                f"Upgrade to a live key for full input limits."
            )
        # Proxy mode not available for trial keys
        from domain.enums import ExecutionMode as _ExecMode
        if _mode_str(body.execution_mode) == "proxy" or body.execution_mode == _ExecMode.PROXY:
            from errors.exceptions import ForbiddenError
            raise ForbiddenError("Proxy mode is not available for trial keys.")

        # Trial rate limit — enforced here since rate_limit middleware runs before auth
        # Global rate limit (60/min) is already enforced by middleware
        # We enforce the stricter trial limit (10/min) here using the same Redis store
        try:
            from cache.rate_limit_store import is_rate_limited
            key_id = getattr(request.state, "key_id", None)
            if key_id:
                trial_id = f"trial:key:{key_id}"
                is_limited, remaining, reset_at = await is_rate_limited(
                    trial_id,
                    limit=settings.trial_rate_limit_per_minute,
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
    cached = await get_cached_result(body.input, det_mode_str, exe_mode_str)
    if cached:
        CACHE_HITS.inc()
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

    result = await run_in_threadpool(
        _gateway.process,
        incoming,
        block_threshold,
        sanitize_threshold,
        pii_block_threshold,
        pii_sanitize_threshold,
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

    source = (
        (body.metadata.source if body.metadata and body.metadata.source else None)
        or getattr(request.state, "key_name", None)
        or "unknown"
    )

    repo = AuditRepository(db)
    await repo.create({
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
        "proxy_interaction_id":  None,
        "severity":              compute_severity(
            decision       = result.decision.decision.value,
            risk_score     = result.decision.risk_score.value,
            primary_reason = result.decision.primary_reason,
        ),
    })

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
    )

    response = _build_response(
        result.decision,
        debug=body.options.debug and getattr(request.state, "is_admin", False)
    )

    await set_cached_result(body.input, det_mode_str, exe_mode_str, response)

    return JSONResponse(content=response)


@router.get("/requests/{trace_id}")
async def get_request(
    trace_id: str,
    request:  Request,
    db:       AsyncSession = Depends(get_db),
):
    repo    = AuditRepository(db)
    dept_id = getattr(request.state, "dept_id", None)

    # Admin keys have no dept_id — use unscoped lookup.
    # All other keys use dept-scoped lookup to prevent cross-dept leakage.
    if dept_id:
        record = await repo.get_by_trace_id_scoped(trace_id, dept_id)
    else:
        record = await repo.get_by_trace_id(trace_id)

    if not record:
        raise NotFoundError("request", trace_id)

    # Enrich with human-readable names
    dept_name = None
    app_name  = None
    if record.dept_id:
        try:
            import uuid
            from db.repositories.department import DepartmentRepository
            dept_repo = DepartmentRepository(db)
            dept      = await dept_repo.get_by_id(uuid.UUID(record.dept_id))
            dept_name = dept.name if dept else None
        except Exception:
            pass
    if record.app_id:
        try:
            import uuid
            from db.repositories.application import ApplicationRepository
            app_repo = ApplicationRepository(db)
            app      = await app_repo.get_by_id(uuid.UUID(record.app_id))
            app_name = app.name if app else None
        except Exception:
            pass

    # Build base response
    response = {
        "trace_id":       record.trace_id,
        "timestamp":      record.created_at.isoformat(),
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
            import logging
            logging.getLogger("wrapsec.ai").error(
                f"Failed to join proxy_interactions for trace_id={trace_id}: {exc}"
            )

    return JSONResponse(content=response)