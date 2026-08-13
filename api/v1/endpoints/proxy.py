# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
AI Interaction Firewall -- OpenAI-compatible proxy endpoint.

POST /v1/chat/completions

Developer change required:
    Before: client = OpenAI(api_key="sk-openai-...", base_url="https://api.openai.com/v1")
    After:  client = OpenAI(api_key="wsk_live_...",   base_url="http://localhost:8000/v1")
    model:  "gpt-4o"  ->  "openai/gpt-4o"

WrapSec enforces security on input and output.
The provider API key is stored server-side -- the client only holds a WrapSec key.

Request headers:
    Authorization: Bearer wsk_live_...         required
    X-WrapSec-Mode: fast | full               optional, default: fast
    X-WrapSec-Scan-All-Messages: true|false   optional, default: false
    X-WrapSec-Inline-Meta: true|false         optional, default: false
    Idempotency-Key: <uuid>                   optional

Response headers added to every response:
    X-WrapSec-Trace-Id
    X-WrapSec-Input-Decision
    X-WrapSec-Input-Primary-Reason
    X-WrapSec-Input-Confidence
    X-WrapSec-Input-Sanitized
    X-WrapSec-Output-Decision
    X-WrapSec-Output-Sanitized
    X-WrapSec-Execution-Status
    X-WrapSec-Provider
    X-WrapSec-Model
    X-WrapSec-Latency-Ms
"""

import copy
import logging
import time

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal
from api.v1.dependencies.db import get_db
from config.settings import get_settings
from db.models import ProxyInteractionModel, ProxyProviderConfigModel
from db.repositories.audit import AuditRepository
from domain.entities.principal import Principal
from domain.entities.request import IncomingRequest, RequestMetadata
from domain.enums import DetectionMode, ExecutionMode
from domain.value_objects.severity import compute_severity
from domain.value_objects.trace_id import TraceId
from engine.guardrails.output_guard import OutputGuard
from engine.proxy.router import (
    parse_model_string,
    resolve_provider,
    resolve_provider_from_dict,
)
from observability.metrics import record_proxy_request, record_request
from services.gateway.service import GatewayService
from services.policy_resolver import resolve_policy
from services.time import utc_now
from services.webhooks.emitter import emit_from_audit_background

router = APIRouter()
logger = logging.getLogger("wrapsec.proxy")

_gateway      = GatewayService()
_output_guard = OutputGuard()

# Execution status constants
STATUS_SUCCESS        = "SUCCESS"
STATUS_BLOCKED        = "BLOCKED"
STATUS_OUTPUT_BLOCKED = "OUTPUT_BLOCKED"
STATUS_FAILED         = "FAILED"
STATUS_TIMEOUT        = "TIMEOUT"


def _build_proxy_audit_dict(
    *,
    trace_id:       str,
    tenant_id,
    gd,
    key_id,
    mode:           str,
    input_decision: str,
    input_reason:   str | None,
    input_conf:     float,
    input_threats:  list[str],
) -> dict:
    """
    Assemble the audit-shaped dict handed to the webhook emitter for the
    proxy input decision. Kept as a module-level helper so the handler
    body stays lean and this construction cost is only paid when the
    background task fires (BackgroundTasks executes AFTER the response
    body is on the wire).

    The proxy path has no unified audit dict of its own -- _log_interaction
    builds a different shape internally -- so this helper mirrors the
    subset of audit_log fields the proxy can populate at input-decision
    time. Fields not applicable to the proxy path (input_hash, dept_id,
    app_id, ...) are simply omitted; the emitter's whitelist drops them.
    """
    proxy_risk = gd.risk_score.value if hasattr(gd, "risk_score") else 0.0
    return {
        "trace_id":        trace_id,
        "tenant_id":       tenant_id,
        "decision":        input_decision,
        "risk_score":      proxy_risk,
        "primary_reason":  input_reason,
        "confidence":      input_conf,
        "confidence_band": (
            "HIGH" if input_conf >= 0.7 else "MEDIUM" if input_conf >= 0.4 else "LOW"
        ),
        "threats":         input_threats,
        "detection_mode":  mode,
        "execution_mode":  "proxy",
        "source":          "proxy",
        "key_id":          key_id,
        "severity":        compute_severity(
            decision       = input_decision,
            risk_score     = proxy_risk,
            primary_reason = input_reason,
        ),
    }


# ── Request schema ─────────────────────────────────────────────────────────────

class ProxyChatRequest(BaseModel):
    model:       str | None    = None
    messages:    list[dict]
    temperature: float | None  = None
    max_tokens:  int | None    = None
    top_p:       float | None  = None

    model_config = {"extra": "forbid"}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_scan_target(messages: list[dict], scan_all: bool) -> str:
    """
    Extract the text to scan from the messages array.

    scan_all=False (default): scan only the last user message.
                              System messages are developer-controlled, not scanned.
    scan_all=True:            scan all user-role messages joined by newline.
                              Catches injections spread across conversation history.

    Raises ValueError if no user messages found.
    """
    user_messages = [m for m in messages if m.get("role") == "user"]
    if not user_messages:
        raise ValueError("No user messages found in messages array.")

    if scan_all:
        return "\n".join(m.get("content", "") for m in user_messages)
    return user_messages[-1].get("content", "")


def _apply_sanitization(
    messages:  list[dict],
    sanitized: str,
    scan_all:  bool,
) -> list[dict]:
    """
    Replace user message content with sanitized version.
    Returns a new list -- does not mutate the original.
    """
    messages = copy.deepcopy(messages)

    user_indices = [i for i, m in enumerate(messages) if m.get("role") == "user"]
    if not user_indices:
        return messages

    if scan_all:
        # Split sanitized text back and reassign to each user message in order
        parts = sanitized.split("\n", len(user_indices) - 1)
        for idx, msg_idx in enumerate(user_indices):
            messages[msg_idx]["content"] = parts[idx] if idx < len(parts) else ""
    else:
        # Replace only the last user message
        messages[user_indices[-1]]["content"] = sanitized

    return messages


def _build_wrapsec_headers(
    trace_id:         str,
    input_decision:   str,
    input_reason:     str,
    input_confidence: float,
    input_sanitized:  bool,
    output_decision:  str | None,
    output_sanitized: bool,
    execution_status: str,
    provider:         str | None,
    model:            str | None,
    latency_ms:       int,
) -> dict:
    headers = {
        "X-WrapSec-Trace-Id":             trace_id,
        "X-WrapSec-Input-Decision":       input_decision,
        "X-WrapSec-Input-Primary-Reason": input_reason,
        "X-WrapSec-Input-Confidence":     str(round(input_confidence, 4)),
        "X-WrapSec-Input-Sanitized":      str(input_sanitized).lower(),
        "X-WrapSec-Output-Decision":      output_decision or "N/A",
        "X-WrapSec-Output-Sanitized":     str(output_sanitized).lower(),
        "X-WrapSec-Execution-Status":     execution_status,
        "X-WrapSec-Provider":             provider or "N/A",
        "X-WrapSec-Model":                model or "N/A",
        "X-WrapSec-Latency-Ms":           str(latency_ms),
    }
    return headers


def _error_response(
    status_code:      int,
    message:          str,
    error_type:       str,
    error_code:       str,
    wrapsec_meta:     dict,
    headers:          dict,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": message,
                "type":    error_type,
                "code":    error_code,
            },
            "wrapsec": wrapsec_meta,
        },
        headers=headers,
    )


async def _log_interaction(
    db:               AsyncSession,
    trace_id:         str,
    key_id:           str | None,
    user_id:          str | None,
    input_raw:        str,
    input_sanitized:  str | None,
    input_decision:   str,
    input_reason:     str,
    input_confidence: float,
    input_threats:    list,
    input_attack_type: str | None,
    provider:         str | None,
    model:            str | None,
    provider_latency: int | None,
    execution_status: str,
    output_raw:       str | None,
    output_sanitized: str | None,
    output_decision:  str | None,
    output_reason:    str | None,
    output_confidence: float | None,
    output_threats:   list | None,
    total_latency_ms: int,
    # Audit fields for audit_logs
    risk_score:       float = 0.0,
    detection_scores: dict | None  = None,
    guardrail_scores: dict | None  = None,
    input_length:     int   = 0,
) -> None:
    try:
        # Honor data_storage_mode:
        #   full   -> store raw and sanitized as captured
        #   masked -> null out raw fields; keep sanitized (already redacted upstream)
        #   none   -> null out both raw and sanitized (strict compliance)
        mode = (get_settings().data_storage_mode or "masked").lower()
        if mode == "none":
            stored_input_raw        = None
            stored_input_sanitized  = None
            stored_output_raw       = None
            stored_output_sanitized = None
        elif mode == "masked":
            stored_input_raw        = None
            stored_input_sanitized  = input_sanitized
            stored_output_raw       = None
            stored_output_sanitized = output_sanitized
        else:  # "full" or any unrecognized value falls back to full for backwards compat
            stored_input_raw        = input_raw
            stored_input_sanitized  = input_sanitized
            stored_output_raw       = output_raw
            stored_output_sanitized = output_sanitized

        # 1. Insert into proxy_interactions
        interaction = ProxyInteractionModel(
            trace_id              = trace_id,
            key_id                = key_id,
            user_id               = user_id,
            input_raw             = stored_input_raw,
            input_sanitized       = stored_input_sanitized,
            input_decision        = input_decision,
            input_primary_reason  = input_reason,
            input_confidence      = input_confidence,
            input_threats         = input_threats,
            input_attack_type     = input_attack_type,
            provider              = provider,
            model                 = model,
            provider_latency_ms   = provider_latency,
            execution_status      = execution_status,
            output_raw            = stored_output_raw,
            output_sanitized      = stored_output_sanitized,
            output_decision       = output_decision,
            output_primary_reason = output_reason,
            output_confidence     = output_confidence,
            output_threats        = output_threats,
            behavior_flag         = None,
            output_flags          = None,
            total_latency_ms      = total_latency_ms,
            created_at            = utc_now(),
        )
        db.add(interaction)
        await db.flush()   # flush to get interaction.id before audit_logs insert

        # 2. Insert into audit_logs with FK
        repo = AuditRepository(db)
        await repo.create({
            "trace_id":              trace_id,
            "decision":              input_decision,
            "risk_score":            risk_score,
            "threats":               input_threats or [],
            "input_hash":            "proxy:" + trace_id,
            "detection_mode":        "fast",
            "execution_mode":        "proxy",
            "llm_invoked":           False,
            "latency_ms":            float(total_latency_ms),
            "detection_scores":      detection_scores or {},
            "guardrail_scores":      guardrail_scores or {},
            "key_id":                key_id,
            "primary_reason":        input_reason,
            "confidence":            input_confidence,
            "confidence_band":       "HIGH" if input_confidence >= 0.7 else "MEDIUM" if input_confidence >= 0.4 else "LOW",
            "input_length":          input_length,
            "proxy_interaction_id":  interaction.id,
        })

    except Exception as exc:
        logger.error(f"Failed to log proxy interaction trace_id={trace_id}: {exc}")


# ── Endpoint ───────────────────────────────────────────────────────────────────

@router.post("/chat/completions", response_model=None)
async def proxy_chat_completions(
    body:             ProxyChatRequest,
    request:          Request,
    background_tasks: BackgroundTasks,
    db:               AsyncSession = Depends(get_db),
    _principal:       Principal    = Depends(get_current_principal),
):
    """
    OpenAI-compatible proxy endpoint. Scans input, forwards to the configured LLM provider,
    then scans the output before returning it to the caller.

    Pipeline (steps executed in order):
      0. Trial key guard - proxy mode blocked for trial keys.
      1. Parse model string - must be in "provider/model" format (e.g. "openai/gpt-4o").
      2. Load proxy provider config - keyed to the API key's key_id.
      3. Read WrapSec request headers (X-WrapSec-Mode, X-WrapSec-Scan-All-Messages, X-WrapSec-Inline-Meta).
      4. Extract scan target - last user message, or all user messages if scan_all=true.
      5. Run input detection pipeline (GatewayService).
      6. Handle input BLOCK - log and return 400.
      7. Apply SANITIZE to messages - replaces user content with sanitized version.
      8. Forward to provider - resolve provider instance and call chat_completions.
      9. Run OutputGuard on provider response.
     10. Handle output BLOCK - log and return 400.
     11. Log successful interaction to proxy_interactions + audit_logs.
     12. Record proxy metrics (non-blocking).
     13. Return OpenAI-compatible response with WrapSec response headers.

    All execution paths write to audit_logs. X-WrapSec-* headers are always included.
    Auth: any valid live API key (trial keys are rejected).
    """
    wall_start = time.monotonic()
    trace_id   = str(TraceId.generate())
    key_id     = getattr(request.state, "key_id",    None)
    tenant_id  = getattr(request.state, "tenant_id", None)

    # -- 0. Trial key check - proxy mode not available for trial keys --
    key_type = getattr(request.state, "key_type", "live")
    if key_type == "trial":
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Proxy mode is not available for trial keys. Upgrade to a live key.",
                    "type":    "forbidden",
                    "code":    "trial_proxy_disabled",
                }
            },
            headers={"X-WrapSec-Trace-Id": trace_id},
        )

    # -- 1. Parse model string if provided; deferred resolution happens after step 3 --
    provider_name, model_name = None, None
    if body.model is not None:
        try:
            provider_name, model_name = parse_model_string(body.model)
        except ValueError as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": str(exc),
                        "type":    "invalid_request_error",
                        "code":    "invalid_model_format",
                    }
                },
                headers={"X-WrapSec-Trace-Id": trace_id},
            )

    # -- 2. Resolve policy (moved early - used for both detection and proxy fallback) --
    policy, _ = await resolve_policy(
        db        = db,
        tenant_id = tenant_id,
        dept_id   = getattr(request.state, "dept_id", None),
        app_id    = getattr(request.state, "app_id",  None),
    )

    # -- 3. Load proxy provider config - dept/app override wins, tenant config is fallback --
    dept_proxy_cfg = policy.get("proxy_provider")  # resolved by policy_resolver (dept/app override)
    config = None
    if not dept_proxy_cfg:
        result = await db.execute(
            select(ProxyProviderConfigModel).where(
                ProxyProviderConfigModel.tenant_id == tenant_id
            )
        )
        config = result.scalar_one_or_none()

    if not config and not dept_proxy_cfg:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": (
                        "No proxy provider configured for this API key or department. "
                        "Configure a provider via PUT /v1/settings/proxy or the department policy."
                    ),
                    "type":    "invalid_request_error",
                    "code":    "proxy_not_configured",
                }
            },
        )

    # -- 3b. Resolve model from default_model if not supplied in request --
    if provider_name is None:
        default_model = (
            config.default_model if config
            else (dept_proxy_cfg or {}).get("default_model")
        )
        if not default_model:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": (
                            "No model specified and no default_model configured. "
                            "Pass 'model' in the request body or set a default_model in proxy settings."
                        ),
                        "type":    "invalid_request_error",
                        "code":    "model_required",
                    }
                },
                headers={"X-WrapSec-Trace-Id": trace_id},
            )
        try:
            provider_name, model_name = parse_model_string(default_model)
        except ValueError as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": str(exc),
                        "type":    "invalid_request_error",
                        "code":    "invalid_model_format",
                    }
                },
                headers={"X-WrapSec-Trace-Id": trace_id},
            )

    # -- 4. Read WrapSec request headers --
    scan_all = request.headers.get("X-WrapSec-Scan-All-Messages", "false").lower() == "true"
    mode     = request.headers.get("X-WrapSec-Mode", "fast").lower()
    inline   = request.headers.get("X-WrapSec-Inline-Meta", "false").lower() == "true"

    if mode not in ("fast", "full"):
        mode = "fast"

    # -- 5. Extract scan target --
    try:
        scan_input = _extract_scan_target(body.messages, scan_all)
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": str(exc),
                    "type":    "invalid_request_error",
                    "code":    "invalid_messages",
                }
            },
        )

    # -- 6. Run detection pipeline --
    incoming = IncomingRequest(
        input          = scan_input,
        detection_mode = DetectionMode(mode),
        execution_mode = ExecutionMode("scan_only"),  # gateway does not call LLM -- we handle that
        metadata       = RequestMetadata(
            tenant_id = getattr(request.state, "tenant_id", None),
            user_id   = None,
        ),
    )
    # Override trace_id so it matches what we log
    incoming.trace_id = trace_id  # type: ignore[assignment]

    pii_policy      = policy.get("guardrails", {}).get("pii", {})
    toxicity_policy = policy.get("guardrails", {}).get("toxicity", {})
    gateway_result = await _gateway.process(
        incoming,
        policy["thresholds"]["block"],
        policy["thresholds"]["sanitize"],
        pii_policy.get("block_threshold"),
        pii_policy.get("sanitize_threshold"),
        toxicity_policy.get("block_threshold"),
        toxicity_policy.get("sanitize_threshold"),
        policy["detection"]["rule_enabled"],
        policy["detection"]["ml_enabled"],
        policy["detection"]["llm_enabled"] if mode == "full" else False,
        policy["llm"],
    )

    gd             = gateway_result.decision
    input_decision = gd.decision.value          # ALLOW / BLOCK / SANITIZE
    input_reason   = gd.primary_reason
    input_conf     = gd.confidence
    input_threats  = [t.value for t in gd.threats]
    input_attack   = input_threats[0] if input_threats else None
    input_sanit    = gd.sanitized_input

    # Compute once; reused at every _log_interaction call site below
    _det_scores = {
        "rule": gd.layer_scores.rule_score,
        "ml":   gd.layer_scores.ml_score,
        "llm":  gd.layer_scores.llm_score,
    } if gd.layer_scores else {}
    _grd_scores = {"pii": gd.layer_scores.pii_score} if gd.layer_scores else {}
    if gd.layer_scores and gd.layer_scores.toxicity_score > 0.0:
        _grd_scores["toxicity"] = gd.layer_scores.toxicity_score

    # Schedule webhook emit for the input decision. Runs AFTER the response
    # body is on the wire (BackgroundTasks semantics), so the proxy path is
    # immune to webhook subsystem latency and failures. Output-decision
    # emit lands with the output-block webhook event in a later commit.
    background_tasks.add_task(
        emit_from_audit_background,
        _build_proxy_audit_dict(
            trace_id       = trace_id,
            tenant_id      = tenant_id,
            gd             = gd,
            key_id         = key_id,
            mode           = mode,
            input_decision = input_decision,
            input_reason   = input_reason,
            input_conf     = input_conf,
            input_threats  = input_threats,
        ),
    )

    # -- 6. Handle input BLOCK --
    if input_decision == "BLOCK":
        total_ms = int((time.monotonic() - wall_start) * 1000)
        headers  = _build_wrapsec_headers(
            trace_id, input_decision, input_reason, input_conf,
            False, None, False, STATUS_BLOCKED,
            None, None, total_ms,
        )
        await _log_interaction(
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            input_raw=scan_input, input_sanitized=None,
            input_decision=input_decision, input_reason=input_reason,
            input_confidence=input_conf, input_threats=input_threats,
            input_attack_type=input_attack,
            provider=None, model=None, provider_latency=None,
            execution_status=STATUS_BLOCKED,
            output_raw=None, output_sanitized=None,
            output_decision=None, output_reason=None,
            output_confidence=None, output_threats=None,
            total_latency_ms=total_ms,
            risk_score       = gd.risk_score.value if hasattr(gd, "risk_score") else 0.0,
            detection_scores = _det_scores,
            guardrail_scores = _grd_scores,
            input_length     = len(scan_input),
        )
        return _error_response(
            status_code  = 400,
            message      = "Request blocked by security policy.",
            error_type   = "invalid_request_error",
            error_code   = "input_blocked",
            wrapsec_meta = {
                "trace_id":             trace_id,
                "decision":             input_decision,
                "input_primary_reason": input_reason,
                "input_threats":        input_threats,
                "input_confidence":     round(input_conf, 4),
                "execution_status":     STATUS_BLOCKED,
            },
            headers=headers,
        )

    # -- 7. Apply SANITIZE to messages if needed --
    messages = body.messages
    if input_decision == "SANITIZE" and input_sanit:
        messages = _apply_sanitization(messages, input_sanit, scan_all)

    # -- 8. Resolve provider and forward request --
    try:
        if config:
            provider_instance, _ = resolve_provider(provider_name, config)
        else:
            provider_instance, _ = resolve_provider_from_dict(provider_name, dept_proxy_cfg)
    except ValueError as exc:
        total_ms = int((time.monotonic() - wall_start) * 1000)
        logger.error("Provider resolution failed trace_id=%s: %s", trace_id, exc)
        return JSONResponse(
            status_code=500,
            content={"error": {"message": "Provider configuration error.", "type": "provider_error", "code": "provider_config_error"}},
            headers={"X-WrapSec-Trace-Id": trace_id},
        )

    # Build kwargs from explicitly declared request fields only
    kwargs = {}
    if body.temperature is not None:
        kwargs["temperature"] = body.temperature
    if body.max_tokens is not None:
        kwargs["max_tokens"] = body.max_tokens
    if body.top_p is not None:
        kwargs["top_p"] = body.top_p

    provider_latency = None
    provider_response = None

    try:
        provider_response = await provider_instance.chat_completions(
            model    = model_name,
            messages = messages,
            trace_id = trace_id,
            **kwargs,
        )
        provider_latency = provider_response.latency_ms

    except httpx.TimeoutException:
        total_ms = int((time.monotonic() - wall_start) * 1000)
        headers  = _build_wrapsec_headers(
            trace_id, input_decision, input_reason, input_conf,
            input_decision == "SANITIZE", None, False, STATUS_TIMEOUT,
            provider_name, model_name, total_ms,
        )
        await _log_interaction(
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            input_raw=scan_input, input_sanitized=input_sanit,
            input_decision=input_decision, input_reason=input_reason,
            input_confidence=input_conf, input_threats=input_threats,
            input_attack_type=input_attack,
            provider=provider_name, model=model_name, provider_latency=None,
            execution_status=STATUS_TIMEOUT,
            output_raw=None, output_sanitized=None,
            output_decision=None, output_reason=None,
            output_confidence=None, output_threats=None,
            total_latency_ms=total_ms,
            risk_score       = gd.risk_score.value if hasattr(gd, "risk_score") else 0.0,
            detection_scores = _det_scores,
            guardrail_scores = _grd_scores,
            input_length     = len(scan_input),
        )
        return _error_response(
            status_code  = 504,
            message      = "Provider timed out.",
            error_type   = "provider_error",
            error_code   = "provider_timeout",
            wrapsec_meta = {
                "trace_id":         trace_id,
                "decision":         input_decision,
                "execution_status": STATUS_TIMEOUT,
            },
            headers=headers,
        )

    except (httpx.ConnectError, httpx.HTTPStatusError) as exc:
        total_ms = int((time.monotonic() - wall_start) * 1000)
        logger.error("Provider call failed trace_id=%s: %.500s", trace_id, exc)
        headers  = _build_wrapsec_headers(
            trace_id, input_decision, input_reason, input_conf,
            input_decision == "SANITIZE", None, False, STATUS_FAILED,
            provider_name, model_name, total_ms,
        )
        await _log_interaction(
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            input_raw=scan_input, input_sanitized=input_sanit,
            input_decision=input_decision, input_reason=input_reason,
            input_confidence=input_conf, input_threats=input_threats,
            input_attack_type=input_attack,
            provider=provider_name, model=model_name, provider_latency=None,
            execution_status=STATUS_FAILED,
            output_raw=None, output_sanitized=None,
            output_decision=None, output_reason=None,
            output_confidence=None, output_threats=None,
            total_latency_ms=total_ms,
            risk_score       = gd.risk_score.value if hasattr(gd, "risk_score") else 0.0,
            detection_scores = _det_scores,
            guardrail_scores = _grd_scores,
            input_length     = len(scan_input),
        )
        return _error_response(
            status_code  = 502,
            message      = "Provider unreachable. Your request passed security validation but could not be completed.",
            error_type   = "provider_error",
            error_code   = "provider_unreachable",
            wrapsec_meta = {
                "trace_id":         trace_id,
                "decision":         input_decision,
                "execution_status": STATUS_FAILED,
            },
            headers=headers,
        )

    # -- 9. Run OutputGuard on provider response --
    output_result     = _output_guard.inspect(provider_response.content)
    output_decision   = output_result.decision
    output_reason     = output_result.primary_reason
    output_conf       = output_result.confidence
    output_threats    = output_result.threats
    output_sanitized  = output_result.sanitized_text
    output_content    = output_sanitized if output_decision == "SANITIZE" else provider_response.content

    # -- 10. Handle output BLOCK --
    if output_decision == "BLOCK":
        total_ms = int((time.monotonic() - wall_start) * 1000)
        headers  = _build_wrapsec_headers(
            trace_id, input_decision, input_reason, input_conf,
            input_decision == "SANITIZE", output_decision, False,
            STATUS_OUTPUT_BLOCKED, provider_name, model_name, total_ms,
        )
        await _log_interaction(
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            input_raw=scan_input, input_sanitized=input_sanit,
            input_decision=input_decision, input_reason=input_reason,
            input_confidence=input_conf, input_threats=input_threats,
            input_attack_type=input_attack,
            provider=provider_name, model=model_name,
            provider_latency=provider_latency,
            execution_status=STATUS_OUTPUT_BLOCKED,
            output_raw=provider_response.content,
            output_sanitized=None,
            output_decision=output_decision, output_reason=output_reason,
            output_confidence=output_conf, output_threats=output_threats,
            total_latency_ms=total_ms,
            risk_score       = gd.risk_score.value if hasattr(gd, "risk_score") else 0.0,
            detection_scores = _det_scores,
            guardrail_scores = _grd_scores,
            input_length     = len(scan_input),
        )
        return _error_response(
            status_code  = 400,
            message      = "Model response blocked by output security policy.",
            error_type   = "policy_violation",
            error_code   = "output_blocked",
            wrapsec_meta = {
                "trace_id":              trace_id,
                "decision":              input_decision,
                "output_decision":       output_decision,
                "output_primary_reason": output_reason,
                "execution_status":      STATUS_OUTPUT_BLOCKED,
            },
            headers=headers,
        )

    # -- 11. Log successful interaction --
    total_ms         = int((time.monotonic() - wall_start) * 1000)
    execution_status = STATUS_SUCCESS

    await _log_interaction(
        db=db, trace_id=trace_id, key_id=key_id, user_id=None,
        input_raw=scan_input, input_sanitized=input_sanit,
        input_decision=input_decision, input_reason=input_reason,
        input_confidence=input_conf, input_threats=input_threats,
        input_attack_type=input_attack,
        provider=provider_name, model=model_name,
        provider_latency=provider_latency,
        execution_status=execution_status,
        output_raw=provider_response.content,
        output_sanitized=output_sanitized if output_decision == "SANITIZE" else None,
        output_decision=output_decision, output_reason=output_reason,
        output_confidence=output_conf, output_threats=output_threats,
        total_latency_ms=total_ms,
        risk_score       = gd.risk_score.value if hasattr(gd, "risk_score") else 0.0,
            detection_scores = _det_scores,
            guardrail_scores = _grd_scores,
            input_length     = len(scan_input),
    )

    # -- 12. Record proxy metrics --
    try:
        record_proxy_request(
            execution_status = execution_status,
            total_latency_ms = total_ms,
            llm_invoked      = True,
            provider         = provider_name or "unknown",
        )
        record_request(
            decision       = input_decision,
            detection_mode = "fast",
            execution_mode = "proxy",
            latency_ms     = float(total_ms),
            threats        = input_threats or [],
            primary_reason = input_reason,
            key_type       = getattr(request.state, "key_type", "live"),
        )
    except Exception:
        pass  # Never let metrics break the response

    # -- 13. Build OpenAI-compatible response --
    headers = _build_wrapsec_headers(
        trace_id, input_decision, input_reason, input_conf,
        input_decision == "SANITIZE",
        output_decision, output_decision == "SANITIZE",
        execution_status, provider_name, model_name, total_ms,
    )

    response_body = {
        "id":      f"wrapsec-{trace_id}",
        "object":  "chat.completion",
        "model":   provider_response.model,
        "choices": [
            {
                "index":         0,
                "message":       {"role": "assistant", "content": output_content},
                "finish_reason": provider_response.finish_reason,
            }
        ],
    }

    # Optional inline meta field (opt-in via header)
    if inline:
        response_body["wrapsec"] = {
            "trace_id":             trace_id,
            "decision":             input_decision,   # canonical -- same as top-level decision field
            "input_primary_reason": input_reason,
            "input_confidence":     round(input_conf, 4),
            "input_sanitized":      input_decision == "SANITIZE",
            "output_decision":      output_decision,
            "output_sanitized":     output_decision == "SANITIZE",
            "execution_status":     execution_status,
            "provider":             provider_name,
            "model":                provider_response.model,
            "total_latency_ms":     total_ms,
        }

    logger.info(
        f"Proxy request completed -- "
        f"trace_id={trace_id} "
        f"input={input_decision} "
        f"output={output_decision} "
        f"status={execution_status} "
        f"provider={provider_name} "
        f"latency={total_ms}ms"
    )

    return JSONResponse(content=response_body, headers=headers)