# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
import logging
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal
from api.v1.dependencies.db import get_db
from api.v1.dependencies.scope import get_scoped_audit_record
from api.v1.schemas.request import AIRequestSchema, ScanBatchSchema
from api.v1.schemas.response import (
    ErrorEnvelope,
    RequestRecordResponse,
    ScanBatchResponse,
    ScanResponse,
)
from config.settings import get_settings
from db.repositories.audit import AuditRepository
from domain.entities.principal import Principal
from domain.entities.request import (
    IncomingRequest,
    RequestContext,
    RequestMetadata,
    RequestOptions,
)
from domain.enums import DecisionType, DetectionMode, ExecutionMode
from domain.value_objects.severity import compute_severity
from domain.value_objects.trace_id import TraceId
from errors.exceptions import DebugForbiddenError, NotFoundError, RateLimitError
from services.gateway.fanout import (
    DetectionPolicy,
    ScanItem,
    charge_additional_units,
    scan_items,
)
from services.gateway.service import GatewayService
from services.time import to_iso_z
from services.webhooks.emitter import emit_from_audit_background

router   = APIRouter()
_gateway = GatewayService()

# The feature identity carried in `params.feature`. Defined once because two
# separate conditions on this route refuse the SAME capability, and a caller must
# not be able to tell them apart from the response.
_PROXY_EXECUTION = "proxy execution"

# Documented failures for this family, each carrying the canonical error
# envelope. Only errors these routes actually produce are listed: a status
# documented but unreachable is a promise nothing keeps. 401 arrives from the
# auth middleware and applies to every route here.
_UNAUTHORIZED: dict[int | str, dict[str, Any]] = {401: {"model": ErrorEnvelope, "description": "Missing or invalid credentials."}}

_SCAN_ERRORS: dict[int | str, dict[str, Any]] = {
    **_UNAUTHORIZED,
    400: {"model": ErrorEnvelope, "description": "Input exceeds the trial-key character cap."},
    # Only this route and the OpenAI-compatible one honour `Idempotency-Key`;
    # a replay of that key with a DIFFERENT body is refused rather than served
    # the first body. The batch route does not participate.
    409: {"model": ErrorEnvelope, "description": "`Idempotency-Key` was reused with a different request body."},
    403: {"model": ErrorEnvelope, "description": "Debug output requires an admin key, or the requested capability is not served for this caller (`FEATURE_UNAVAILABLE`, with `params.feature` naming it)."},
    422: {"model": ErrorEnvelope, "description": "Request body failed validation."},
    429: {"model": ErrorEnvelope, "description": "Rate limit exceeded: the global, trial, per-application or debug bucket."},
    502: {"model": ErrorEnvelope, "description": "Proxy execution reached the provider and it returned nothing usable. The scan itself ran and is audited under the returned trace_id."},
}

_BATCH_ERRORS: dict[int | str, dict[str, Any]] = {
    **_UNAUTHORIZED,
    400: {"model": ErrorEnvelope, "description": "An item exceeds the trial-key character cap."},
    422: {"model": ErrorEnvelope, "description": "Request body failed validation, including the batch-size and per-item length caps."},
    429: {"model": ErrorEnvelope, "description": "Rate limit exceeded. A batch is charged as N units, not one."},
}

# The 422 below corrects a SHAPE, it does not add a promise. This route takes one
# unconstrained path string and nothing else -- no query, header or body param --
# so request validation cannot fail on it; measured, not assumed. FastAPI
# publishes a 422 for every parameterized route regardless, and the entry it
# generates names `HTTPValidationError`, a body this application never emits: a
# validation failure anywhere is answered by the global handler with the catalog
# envelope. The generated entry cannot be dropped (a declared response overrides
# it, nothing deletes it), so it is declared with the shape a caller would
# actually receive and the description says plainly that nothing reaches it.
_RECORD_ERRORS: dict[int | str, dict[str, Any]] = {
    **_UNAUTHORIZED,
    404: {"model": ErrorEnvelope, "description": "No such trace_id, or it belongs to another scope."},
    422: {"model": ErrorEnvelope, "description": "Request validation failed. Published for every parameterized route; this one validates nothing, so it is not reachable here."},
    # The global limiter covers the whole `/v1/ai` prefix, so this read-back
    # shares the scan routes' bucket even though it scans nothing.
    429: {"model": ErrorEnvelope, "description": "Rate limit exceeded: this route shares the global `/v1/ai` bucket."},
}


def _mode_str(value) -> str:
    """Extract clean string from enum or string -- always returns lowercase."""
    return str(value).split(".")[-1].lower()


def restrict_layer_scores(body: dict) -> dict:
    """
    Drop the numeric `score` from every entry in `assessment.layers`, leaving
    the layer's name and its ALLOW/SANITIZE/BLOCK classification.

    What this removes and why. A per-layer score is a targeting signal: it says
    how much each detector contributed, so an author reworking a payload learns
    which layer to work against and how far it has to move. That makes evasion
    cheaper in a way the aggregate does not, because the aggregate cannot say
    where the signal came from.

    What it does NOT claim. It is not threshold confidentiality. `risk_score`
    and `decision` are returned to every caller, and a binary search over them
    recovers a threshold to six decimal places in about two dozen probes
    without reading any layer field -- measured, not assumed. Nor does it
    eliminate targeting: the classification is deliberately preserved, so a
    caller can still tell which layer is in which bucket. It narrows a float to
    three states.

    Stated this way on purpose. A control justified as "keeps thresholds
    secret" is one somebody later disproves in an afternoon and removes,
    because the claim is false and the removal looks like cleanup.

    Returns a new object; the caller's dict is not mutated, which matters
    because one of the two call sites is holding a cached body that other
    requests will read again.
    """
    assessment = body.get("assessment")
    if not isinstance(assessment, dict) or not isinstance(assessment.get("layers"), list):
        return body

    return {
        **body,
        "assessment": {
            **assessment,
            "layers": [
                {k: v for k, v in layer.items() if k != "score"}
                if isinstance(layer, dict) else layer
                for layer in assessment["layers"]
            ],
        },
    }


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

    # Source-aware posture, present only when provenance shifted the thresholds.
    # Additive and optional -- absent on the feature-off path, so back-compat is
    # preserved for every existing caller.
    if getattr(decision, "posture", None):
        assessment["posture"] = decision.posture

    response["assessment"] = assessment
    return response


def _build_audit_data(
    *,
    request,
    result,
    trace_id_str:  str,
    det_mode_str:  str,
    exe_mode_str:  str,
    policy_source: str | None,
    source:        str,
    user_id:       str | None,
    input_length:  int,
    session_id:    str | None,
    turn_index:    int | None,
    run_id:        str | None,
    input_source:  str,
) -> dict:
    """Project a GatewayResult + request context into the audit row dict.

    Single source of truth shared by the single-scan and batch endpoints so the
    persisted shape (and the webhook payload derived from it) can never drift
    between the two paths.
    """
    decision = result.decision

    detection_scores = {}
    guardrail_scores = {}
    if decision.layer_scores:
        detection_scores = {
            "rule": decision.layer_scores.rule_score,
            "ml":   decision.layer_scores.ml_score,
            "llm":  decision.layer_scores.llm_score,
        }
        guardrail_scores = {
            "pii": decision.layer_scores.pii_score,
        }
        if decision.layer_scores.toxicity_score > 0.0:
            guardrail_scores["toxicity"] = decision.layer_scores.toxicity_score

    return {
        "trace_id":              trace_id_str,
        "decision":              decision.decision.value,
        "risk_score":            decision.risk_score.value,
        "threats":               [t.value for t in decision.threats],
        "input_hash":            result.audit_log.input_hash,
        "detection_mode":        det_mode_str,
        "execution_mode":        exe_mode_str,
        "llm_invoked":           decision.llm_invoked,
        "latency_ms":            round(decision.latency_ms, 2),
        "detection_scores":      detection_scores,
        "guardrail_scores":      guardrail_scores,
        "tenant_id":             getattr(request.state, "tenant_id", None),
        "source":                source,
        "user_id":               user_id,
        "key_id":                getattr(request.state, "key_id",     None),
        "ip_address":            getattr(request.state, "ip_address",  None),
        "user_agent":            getattr(request.state, "user_agent",  None),
        "attribution_verified":  False,
        "app_id":                getattr(request.state, "app_id",     None),
        "dept_id":               getattr(request.state, "dept_id",    None),
        "policy_source":         policy_source,
        "primary_reason":        decision.primary_reason,
        "confidence":            decision.confidence,
        "confidence_band":       decision.confidence_band,
        "input_length":          input_length,
        "session_id":            session_id,
        "turn_index":            turn_index,
        "run_id":                run_id,
        "input_source":          input_source,
        "proxy_interaction_id":  None,
        "severity":              compute_severity(
            decision       = decision.decision.value,
            risk_score     = decision.risk_score.value,
            primary_reason = decision.primary_reason,
        ),
    }


def _build_cache_hit_audit(
    request,
    body,
    cached:       dict,
    det_mode_str: str,
    exe_mode_str: str,
) -> dict:
    """Project a semantic-cache-hit response into an audit row.

    A cache hit skips the detection pipeline, so there is no GatewayResult; the
    row is rebuilt from the cached decision plus the request's attribution. It is
    tenant-attributed so it lands in tenant-scoped audit reads and the hash chain
    -- otherwise repeated allowed prompts vanish from the audit trail. policy_source
    'cache' and a 'cache:'-prefixed input_hash mark its origin.
    """
    decision       = cached.get("decision", "ALLOW")
    risk_score     = cached.get("risk_score", 0.0)
    primary_reason = cached.get("primary_reason")
    processing     = cached.get("processing", {})
    source = (
        (body.metadata.source if body.metadata and body.metadata.source else None)
        or getattr(request.state, "key_name", None)
        or "unknown"
    )
    return {
        "trace_id":             cached.get("trace_id"),
        "decision":             decision,
        "risk_score":           risk_score,
        "threats":              cached.get("threats", []),
        "input_hash":           "cache:" + hashlib.sha256(body.input.encode()).hexdigest()[:64],
        "detection_mode":       det_mode_str,
        "execution_mode":       exe_mode_str,
        "llm_invoked":          processing.get("llm_invoked", False),
        "latency_ms":           round(processing.get("latency_ms", 0.0), 2),
        "detection_scores":     {},
        "guardrail_scores":     {},
        "tenant_id":            getattr(request.state, "tenant_id", None),
        "source":               source,
        "user_id":              body.metadata.user_id if body.metadata else None,
        "key_id":               getattr(request.state, "key_id",     None),
        "ip_address":           getattr(request.state, "ip_address",  None),
        "user_agent":           getattr(request.state, "user_agent",  None),
        "attribution_verified": False,
        "app_id":               getattr(request.state, "app_id",     None),
        "dept_id":              getattr(request.state, "dept_id",    None),
        "policy_source":        "cache",
        "primary_reason":       primary_reason,
        "confidence":           cached.get("confidence"),
        "confidence_band":      cached.get("confidence_band"),
        "input_length":         len(body.input),
        "session_id":           body.session_id,
        "turn_index":           body.turn_index,
        "run_id":               body.run_id,
        "input_source":         body.input_source,
        "proxy_interaction_id": None,
        "severity":             compute_severity(
            decision       = decision,
            risk_score     = risk_score,
            primary_reason = primary_reason,
        ),
    }


@router.post(
    "/request",
    response_model               = ScanResponse,
    # Absence is contractual here: `sanitized_input`, `output`, `debug`,
    # `assessment.posture` and a restricted caller's `layers[].score` are keys the
    # handler never sets, and they must stay missing rather than appear as null.
    # exclude_unset drops exactly those while keeping a key the handler set to
    # None -- `primary_reason: null` survives. exclude_none could not tell the two
    # apart.
    response_model_exclude_unset = True,
    responses                    = _SCAN_ERRORS,
)
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
        # Proxy mode not available for trial keys.
        #
        # FEATURE_UNAVAILABLE, not FORBIDDEN: nothing about this caller's
        # permissions is wrong, and nothing about the request is. The capability
        # is simply not served for this credential. FORBIDDEN renders "You do not
        # have permission to perform this action", which sends the reader looking
        # for a role to change.
        #
        # The public body says only WHICH feature. That the cause is the
        # credential's class stays in the log line -- the other producer of this
        # code on this route is a disabled detection layer, and a caller who
        # could tell the two apart would be reading tenant configuration out of
        # an error message.
        from domain.enums import ExecutionMode as _ExecMode
        if _mode_str(body.execution_mode) == "proxy" or body.execution_mode == _ExecMode.PROXY:
            from errors.exceptions import FeatureUnavailableError
            raise FeatureUnavailableError(
                _PROXY_EXECUTION,
                debug_message="proxy execution refused: trial credential",
            )

        # Trial rate limit - enforced here since rate_limit middleware runs before auth
        # Global rate limit (60/min) is already enforced by middleware
        # We enforce the stricter trial limit (10/min) here using the same Redis store
        try:
            from cache.rate_limit_store import is_rate_limited
            key_id = getattr(request.state, "key_id", None)
            if key_id:
                trial_id = f"trial:key:{key_id}"
                is_limited, _remaining, _reset_at = await is_rate_limited(
                    trial_id,
                    limit=_settings.trial_rate_limit_per_minute,
                )
                if is_limited:
                    raise RateLimitError()
        except RateLimitError:
            raise
        except Exception:
            pass  # Fail open if Redis unavailable

    det_mode_str = _mode_str(body.detection_mode)
    exe_mode_str = _mode_str(body.execution_mode)

    # Policy is resolved BEFORE the cache is consulted, because the cache key
    # has to name the scope a verdict was reached in. Resolution runs the
    # department and application layers, which may tighten below the tenant's
    # policy -- so a key naming only the tenant let a stricter department read a
    # laxer one's cached ALLOW, with its own policy never consulted. Resolution
    # is a DB read on a path that previously skipped it; the miss path pays the
    # same read either way, and correctness here outranks a hit-path saving.
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
        # Was 422 VALIDATION_ERROR, which was wrong twice over: the submitted
        # data is valid (the same body succeeds where the layer is enabled), and
        # `llm_enabled` is resolved tenant/department/application policy that
        # this caller cannot set and usually cannot read. It is a capability
        # decision, not a validation result, and it is deliberately
        # indistinguishable from the trial refusal above.
        #
        # `execution_mode` is NOT reported in invalid_params: the field is not
        # invalid, and naming it would tell the caller to change a value that is
        # correct.
        from errors.exceptions import FeatureUnavailableError
        raise FeatureUnavailableError(
            _PROXY_EXECUTION,
            debug_message="proxy execution refused: llm detection layer disabled by policy",
        )

    pii_policy             = policy.get("guardrails", {}).get("pii", {})
    pii_block_threshold    = pii_policy.get("block_threshold",    None)
    pii_sanitize_threshold = pii_policy.get("sanitize_threshold", None)

    toxicity_policy             = policy.get("guardrails", {}).get("toxicity", {})
    toxicity_block_threshold    = toxicity_policy.get("block_threshold",    None)
    toxicity_sanitize_threshold = toxicity_policy.get("sanitize_threshold", None)

    # Who may see per-layer scores. Computed before the cache is consulted so
    # the fresh path and the cache-hit path below decide from the same answer.
    #
    # The same predicate `/v1/settings` and `/health/config` use: a per-layer
    # score is the finest-grained calibration signal the response carries, so
    # the caller classes withheld from the others are withheld from this too.
    # A live API key resolves to DEVELOPER and holds it; trial keys and VIEWER
    # do not.
    from api.v1.dependencies.auth import holds_permission
    _may_read_layer_scores = holds_permission(request, "settings:read")

    from cache.semantic_cache import (
        get_cached_result,
        policy_identity,
        set_cached_result,
    )
    from observability.metrics import CACHE_HITS, CACHE_MISSES
    _tenant_id = getattr(request.state, "tenant_id", None) or "global"
    _policy_id = policy_identity(
        block_threshold             = block_threshold,
        sanitize_threshold          = sanitize_threshold,
        pii_block_threshold         = pii_block_threshold,
        pii_sanitize_threshold      = pii_sanitize_threshold,
        toxicity_block_threshold    = toxicity_block_threshold,
        toxicity_sanitize_threshold = toxicity_sanitize_threshold,
        rule_enabled                = rule_enabled,
        ml_enabled                  = ml_enabled,
        llm_enabled                 = llm_enabled,
        llm_settings                = llm_settings,
    )
    cached = await get_cached_result(
        body.input, det_mode_str, exe_mode_str, _tenant_id,
        _policy_id, body.input_source,
    )
    if cached:
        CACHE_HITS.inc()
        # A FRESH id for this hit, generated the same way a fresh scan generates
        # one. This line is load-bearing, not cosmetic: `audit_logs.trace_id` is
        # UNIQUE, and a single cache entry is served to every repeat of the same
        # prompt within the TTL. Auditing a hit under the cached body's own id
        # would insert that key once per hit -- the first hit writes its row, the
        # second violates the constraint and 500s. That is the cache's NORMAL
        # operating condition, not an edge case, so regenerating here is what
        # keeps repeat hits auditable at all. `tests/integration/
        # test_api_ai_branches.py::test_two_hits_on_one_cached_entry_both_audit`
        # pins it: one unchanging cached body, two hits, both rows land.
        #
        # It corrects attribution as well: the cached body carries the ORIGINAL
        # requester's id, which would be wrong to return and wrong to audit under.
        #
        # It is deliberately NOT `request.state.trace_id`. That value comes from
        # the client's `X-Trace-Id` when it matches the middleware's pattern, and
        # it is used below as the audit row's key -- a column that is UNIQUE and
        # `String(50)`, while the header accepts up to 64 characters. So a caller
        # could pick its own audit key: repeat one and the insert violates the
        # constraint, send a 51-character one and it overflows the column. Either
        # way the request fails, and the caller arranges it.
        #
        # Using a generated id also makes a cache hit behave like a miss: a fresh
        # scan already returns `incoming.trace_id`, which never equalled the
        # header either, so nothing is lost by not matching it here. The header
        # remains the client's own correlation id, which is what it is for.
        cached = {**cached, "trace_id": str(TraceId.generate())}
        # Audit the cache hit too. Every request must land in the tenant audit
        # trail and the tamper-evident hash chain -- otherwise repeated allowed
        # prompts (same tenant, within the TTL) are silently absent from the log,
        # per-source stats, and the chain.
        cache_audit = _build_cache_hit_audit(request, body, cached, det_mode_str, exe_mode_str)
        await AuditRepository(db).create(cache_audit)
        background_tasks.add_task(emit_from_audit_background, cache_audit)
        # Restriction is applied on SERVE, not on store -- see the note at the
        # fresh-response path below for why the cache holds full bodies.
        if not _may_read_layer_scores:
            cached = restrict_layer_scores(cached)
        # Returned as a VALUE, not a JSONResponse: a Response object bypasses the
        # response model entirely, and the cache-hit body would then be the one
        # path in this handler that nothing validates or filters. The cached body
        # was built by the same `_build_response`, so the model applies to it
        # unchanged -- and the restriction above has already run, so what the
        # model sees is what this caller is allowed to see.
        return cached
    CACHE_MISSES.inc()

    incoming = IncomingRequest(
        input          = body.input,
        detection_mode = DetectionMode(det_mode_str),
        execution_mode = ExecutionMode(exe_mode_str),
        model          = body.model,
        input_source   = body.input_source,
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

    # Per-app rate limit - enforced when app_id is known and rate_limit_override is set.
    # Uses a separate per-app bucket so the global middleware bucket is unaffected.
    # Fails open if Redis is unavailable - consistent with all other rate limit checks.
    #
    # Stays BELOW the cache return, where it has always been: a cache hit does
    # not consume an app-bucket slot today, and changing that is a resource-
    # control decision rather than part of closing the policy-scope defect.
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
                    raise RateLimitError()
            except RateLimitError:
                raise
            except Exception:
                pass  # Fail open if Redis unavailable.

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

    source = (
        (body.metadata.source if body.metadata and body.metadata.source else None)
        or getattr(request.state, "key_name", None)
        or "unknown"
    )

    # Single audit dict shared between the DB write and the webhook emit,
    # so the wire payload is a faithful subset of the row that was persisted.
    audit_data = _build_audit_data(
        request       = request,
        result        = result,
        trace_id_str  = str(incoming.trace_id),
        det_mode_str  = det_mode_str,
        exe_mode_str  = exe_mode_str,
        policy_source = policy_source,
        source        = source,
        user_id       = body.metadata.user_id if body.metadata else None,
        input_length  = len(body.input),
        session_id    = body.session_id,
        turn_index    = body.turn_index,
        run_id        = body.run_id,
        input_source  = body.input_source,
    )

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

    # Proxy execution was attempted and the provider returned nothing usable.
    # Reported as a failed execution, not as a successful scan with no output:
    # the gateway used to hand back a placeholder string as `output`, which an
    # integrating application renders to its user as the model's reply.
    #
    # RETURNED rather than raised, so the audit row written above and the
    # webhook emit scheduled with it both still land -- the scan itself ran and
    # its verdict is real evidence. This mirrors how the proxy endpoint reports
    # the same upstream condition. The trace id is the caller's handle on that
    # verdict via GET /v1/ai/requests/{trace_id}.
    if result.provider_error is not None:
        from errors.catalog import ErrorCode
        from errors.response import error_response
        return error_response(
            ErrorCode.LLM_UNAVAILABLE,
            trace_id = str(incoming.trace_id),
        )

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
    # The cache stores the FULL body and the restriction is applied on serve.
    #
    # The alternative -- caching a restricted copy -- looks safer and is worse
    # here: a live API key resolves to DEVELOPER, which holds settings:read, so
    # nearly all scan traffic is authorised. Caching stripped bodies would take
    # scores away from that majority on every cache hit, and make one caller's
    # responses differ depending on whether someone else had scanned the same
    # text first. Keying the cache by permission class instead would double the
    # entries for a distinction almost no traffic makes.
    #
    # What makes storing the full body safe is that there is exactly ONE way
    # out of this handler for a cached body and one for a fresh body, and both
    # pass through restrict_layer_scores under the same flag. A leak needs a
    # THIRD return path added without it -- which is what the cache-isolation
    # test exists to catch.
    cache_body = {k: v for k, v in response.items() if k != "debug"}
    # Written under the same key the lookup used, so an entry is only ever read
    # back by a request resolving to the same policy and carrying the same
    # provenance.
    await set_cached_result(
        body.input, det_mode_str, exe_mode_str, _tenant_id, cache_body,
        _policy_id, body.input_source,
    )

    if not _may_read_layer_scores:
        response = restrict_layer_scores(response)

    return response


@router.post(
    "/scan-batch",
    response_model               = ScanBatchResponse,
    # Same reasoning as the single scan. Note what must NOT be dropped here:
    # `summary.highest_risk_item` and an item's `id` are set to None when the
    # caller sent no id, and stay null.
    response_model_exclude_unset = True,
    responses                    = _BATCH_ERRORS,
)
async def ai_scan_batch(
    body:            ScanBatchSchema,
    request:         Request,
    background_tasks: BackgroundTasks,
    db:              AsyncSession = Depends(get_db),
    _principal:      Principal    = Depends(get_current_principal),
):
    """
    Batch security scan - scan many items in one call.

    Every item runs the SAME detection pipeline as POST /request (scan-only; no
    proxy or LLM forwarding) and is audited independently, so batch scans appear
    in the audit trail and timeline exactly like single scans. Each item carries
    its own input_source, so a RAG caller can scan a page of retrieved chunks
    and drop the ones that come back BLOCK.

    A batch is charged as N units against the caller's rate-limit budget (not 1),
    so it cannot amplify throughput past the per-minute limit. Detection runs
    concurrently (bounded by batch_concurrency); audit writes stay sequential
    because the audit hash-chain is per-tenant. The semantic cache is bypassed.

    Response: { count, summary, results: [{ id, trace_id, decision, assessment }] }.
    Auth: any valid principal (API key). Trial keys keep the single-scan per-item
    input cap.
    """
    from api.v1.dependencies.auth import holds_permission
    _batch_may_read_layer_scores = holds_permission(request, "settings:read")

    _settings    = get_settings()
    items        = body.items
    n            = len(items)
    det_mode_str = _mode_str(body.detection_mode)

    # Trial-key per-item input cap (mirrors the single-scan restriction).
    key_type = getattr(request.state, "key_type", "live")
    if key_type == "trial":
        for idx, item in enumerate(items):
            if len(item.input) > _settings.trial_max_input_chars:
                from errors.exceptions import ValidationError
                raise ValidationError(
                    f"Trial keys are limited to {_settings.trial_max_input_chars} "
                    f"characters per item (item {idx} exceeds it). "
                    f"Upgrade to a live key for full input limits."
                )

    # Charge the batch as N units against the caller's bucket.
    await charge_additional_units(request, n)

    # Resolve policy once - the whole batch shares the caller's tenant/dept/app
    # scope. Per-item scope is not a batch concern.
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

    pii_policy             = policy.get("guardrails", {}).get("pii", {})
    pii_block_threshold    = pii_policy.get("block_threshold",    None)
    pii_sanitize_threshold = pii_policy.get("sanitize_threshold", None)
    toxicity_policy             = policy.get("guardrails", {}).get("toxicity", {})
    toxicity_block_threshold    = toxicity_policy.get("block_threshold",    None)
    toxicity_sanitize_threshold = toxicity_policy.get("sanitize_threshold", None)

    source = getattr(request.state, "key_name", None) or "unknown"

    # Scan concurrently (bounded), then persist sequentially below to keep the
    # audit hash chain in order.
    scanned = await scan_items(
        [ScanItem(input=item.input, input_source=item.input_source) for item in items],
        gateway        = _gateway,
        policy         = DetectionPolicy(
            block_threshold             = block_threshold,
            sanitize_threshold          = sanitize_threshold,
            pii_block_threshold         = pii_block_threshold,
            pii_sanitize_threshold      = pii_sanitize_threshold,
            toxicity_block_threshold    = toxicity_block_threshold,
            toxicity_sanitize_threshold = toxicity_sanitize_threshold,
            rule_enabled                = rule_enabled,
            ml_enabled                  = ml_enabled,
            llm_enabled                 = llm_enabled,
            llm_settings                = llm_settings,
        ),
        detection_mode = DetectionMode(det_mode_str),
        metadata       = RequestMetadata(
            tenant_id = getattr(request.state, "tenant_id", None),
            source    = source,
        ),
    )

    repo    = AuditRepository(db)
    results = []
    summary = {
        "blocked":           0,
        "sanitized":         0,
        "allowed":           0,
        "highest_risk":      0.0,
        "highest_risk_item": None,
        "threats":           [],
    }
    threat_set: set[str] = set()

    for item, (incoming, result) in zip(items, scanned):
        audit_data = _build_audit_data(
            request       = request,
            result        = result,
            trace_id_str  = str(incoming.trace_id),
            det_mode_str  = det_mode_str,
            exe_mode_str  = "scan_only",
            policy_source = policy_source,
            source        = source,
            user_id       = None,
            input_length  = len(item.input),
            session_id    = None,
            turn_index    = None,
            run_id        = None,
            input_source  = item.input_source,
        )
        await repo.create(audit_data)
        background_tasks.add_task(emit_from_audit_background, audit_data)

        decision   = result.decision
        item_resp  = _build_response(
            decision,
            block_threshold    = block_threshold,
            sanitize_threshold = sanitize_threshold,
        )
        # Same restriction as the single scan: a batch is not a way around it.
        if not _batch_may_read_layer_scores:
            item_resp = restrict_layer_scores(item_resp)
        results.append({
            "id":         item.id,
            "trace_id":   str(incoming.trace_id),
            "decision":   decision.decision.value,
            "assessment": item_resp["assessment"],
        })

        dv = decision.decision.value
        if dv == DecisionType.BLOCK.value:
            summary["blocked"] += 1
        elif dv == DecisionType.SANITIZE.value:
            summary["sanitized"] += 1
        else:
            summary["allowed"] += 1

        risk = decision.risk_score.value
        if risk > summary["highest_risk"]:
            summary["highest_risk"]      = risk
            summary["highest_risk_item"] = item.id
        threat_set.update(t.value for t in decision.threats)

    summary["threats"]      = sorted(threat_set)
    summary["highest_risk"] = round(summary["highest_risk"], 4)

    return {"count": n, "summary": summary, "results": results}


@router.get(
    "/requests/{trace_id}",
    response_model               = RequestRecordResponse,
    # `proxy` is absent for a scan-only request rather than null. Every other
    # field here is always set, and the nulls among them are real values.
    response_model_exclude_unset = True,
    responses                    = _RECORD_ERRORS,
)
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
    from api.v1.dependencies.auth import holds_permission
    _may_read_layer_scores = holds_permission(request, "settings:read")

    repo   = AuditRepository(db)
    record = await get_scoped_audit_record(repo, trace_id, request)

    if not record:
        raise NotFoundError(resource="request", identifier=trace_id)

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
            pass  # Best-effort dept-name enrichment; leave None on lookup failure.
    if record.app_id:
        try:
            from db.repositories.application import ApplicationRepository
            app_repo = ApplicationRepository(db)
            app      = await app_repo.get_by_id(uuid.UUID(record.app_id))
            app_name = app.name if app else None
        except Exception:
            pass  # Best-effort app-name enrichment; leave None on lookup failure.

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
        # Agentic + provenance context (drives the drawer's Agent / Content
        # Context sections and a cold ?peek deep-link).
        "run_id":            record.run_id,
        "session_id":        record.session_id,
        "turn_index":        record.turn_index,
        "input_source":      record.input_source,
        # The persisted form of the same per-layer numbers the scan response
        # restricts. Left open, a trial key or VIEWER simply reads back what the
        # scan withheld a moment earlier -- the restriction would hold for one
        # request and not for the record of it. Same predicate, so the two
        # cannot disagree. The keys stay present and empty rather than being
        # dropped, so a consumer reading them does not have to special-case.
        "detection_scores":  (record.detection_scores or {}) if _may_read_layer_scores else {},
        "guardrail_scores":  (record.guardrail_scores or {}) if _may_read_layer_scores else {},
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

    return response