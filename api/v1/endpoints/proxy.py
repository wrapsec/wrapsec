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

import logging
import time
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.db import get_db
from config.settings import get_settings
from db.models import ProxyInteractionModel, ProxyProviderConfigModel
from domain.enums import DetectionMode, ExecutionMode
from domain.entities.request import IncomingRequest, RequestMetadata
from domain.value_objects.trace_id import TraceId
from engine.guardrails.output_guard import OutputGuard
from engine.proxy.router import parse_model_string, resolve_provider
from services.gateway.service import GatewayService

router   = APIRouter()
settings = get_settings()
logger   = logging.getLogger("wrapsec.proxy")

_gateway      = GatewayService()
_output_guard = OutputGuard()

# Execution status constants
STATUS_SUCCESS        = "SUCCESS"
STATUS_BLOCKED        = "BLOCKED"
STATUS_OUTPUT_BLOCKED = "OUTPUT_BLOCKED"
STATUS_FAILED         = "FAILED"
STATUS_TIMEOUT        = "TIMEOUT"


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------

class ProxyChatRequest(BaseModel):
    model:       str
    messages:    list[dict]
    temperature: float | None = None
    max_tokens:  int | None   = None
    top_p:       float | None = None

    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    import copy
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
    detection_scores: dict  = None,
    guardrail_scores: dict  = None,
    input_length:     int   = 0,
) -> None:
    try:
        # 1. Insert into proxy_interactions
        interaction = ProxyInteractionModel(
            trace_id              = trace_id,
            key_id                = key_id,
            user_id               = user_id,
            input_raw             = input_raw,
            input_sanitized       = input_sanitized,
            input_decision        = input_decision,
            input_primary_reason  = input_reason,
            input_confidence      = input_confidence,
            input_threats         = input_threats,
            input_attack_type     = input_attack_type,
            provider              = provider,
            model                 = model,
            provider_latency_ms   = provider_latency,
            execution_status      = execution_status,
            output_raw            = output_raw,
            output_sanitized      = output_sanitized,
            output_decision       = output_decision,
            output_primary_reason = output_reason,
            output_confidence     = output_confidence,
            output_threats        = output_threats,
            behavior_flag         = None,
            output_flags          = None,
            total_latency_ms      = total_latency_ms,
            created_at            = datetime.utcnow(),
        )
        db.add(interaction)
        await db.flush()   # flush to get interaction.id before audit_logs insert

        # 2. Insert into audit_logs with FK
        from db.repositories.audit import AuditRepository
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


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/chat/completions", response_model=None)
async def proxy_chat_completions(
    body:    ProxyChatRequest,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    wall_start = time.monotonic()
    trace_id   = str(TraceId.generate())
    key_id     = getattr(request.state, "key_id", None)

    # -- 0. Trial key check — proxy mode not available for trial keys --
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
        )

    # -- 1. Parse model string --
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
        )

    # -- 2. Load proxy provider config --
    result = await db.execute(
        select(ProxyProviderConfigModel).where(
            ProxyProviderConfigModel.key_id == key_id
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": (
                        "No proxy provider configured for this API key. "
                        "Configure a provider via PUT /v1/settings/proxy."
                    ),
                    "type":    "invalid_request_error",
                    "code":    "proxy_not_configured",
                }
            },
        )

    # -- 3. Read WrapSec headers --
    scan_all = request.headers.get("X-WrapSec-Scan-All-Messages", "false").lower() == "true"
    mode     = request.headers.get("X-WrapSec-Mode", "fast").lower()
    inline   = request.headers.get("X-WrapSec-Inline-Meta", "false").lower() == "true"

    if mode not in ("fast", "full"):
        mode = "fast"

    # -- 4. Extract scan target --
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

    # -- 5. Run detection pipeline --
    from services.policy_resolver import resolve_policy
    policy, _ = await resolve_policy(
        db        = db,
        tenant_id = getattr(request.state, "tenant_id", None),
        dept_id   = getattr(request.state, "dept_id",   None),
        app_id    = getattr(request.state, "app_id",    None),
    )

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

    pii_policy             = policy.get("guardrails", {}).get("pii", {})
    gateway_result = await run_in_threadpool(
        _gateway.process,
        incoming,
        policy["thresholds"]["block"],
        policy["thresholds"]["sanitize"],
        pii_policy.get("block_threshold"),
        pii_policy.get("sanitize_threshold"),
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
            detection_scores = {
                "rule": gd.layer_scores.rule_score,
                "ml":   gd.layer_scores.ml_score,
                "llm":  gd.layer_scores.llm_score,
            } if gd.layer_scores else {},
            guardrail_scores = {"pii": gd.layer_scores.pii_score} if gd.layer_scores else {},
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
        provider_instance, _ = resolve_provider(provider_name, config)
    except ValueError as exc:
        total_ms = int((time.monotonic() - wall_start) * 1000)
        logger.error(f"Provider resolution failed trace_id={trace_id}: {exc}")
        return JSONResponse(
            status_code=500,
            content={"error": {"message": str(exc), "type": "provider_error", "code": "provider_config_error"}},
        )

    # Build kwargs from request body -- pass through model params unchanged
    kwargs = {}
    if body.temperature is not None:
        kwargs["temperature"] = body.temperature
    if body.max_tokens is not None:
        kwargs["max_tokens"] = body.max_tokens
    if body.top_p is not None:
        kwargs["top_p"] = body.top_p
    # Pass through any extra fields the client sent
    for k, v in (body.model_extra or {}).items():
        kwargs[k] = v

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
            detection_scores = {
                "rule": gd.layer_scores.rule_score,
                "ml":   gd.layer_scores.ml_score,
                "llm":  gd.layer_scores.llm_score,
            } if gd.layer_scores else {},
            guardrail_scores = {"pii": gd.layer_scores.pii_score} if gd.layer_scores else {},
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
        logger.error(f"Provider call failed trace_id={trace_id}: {exc}")
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
            detection_scores = {
                "rule": gd.layer_scores.rule_score,
                "ml":   gd.layer_scores.ml_score,
                "llm":  gd.layer_scores.llm_score,
            } if gd.layer_scores else {},
            guardrail_scores = {"pii": gd.layer_scores.pii_score} if gd.layer_scores else {},
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
            detection_scores = {
                "rule": gd.layer_scores.rule_score,
                "ml":   gd.layer_scores.ml_score,
                "llm":  gd.layer_scores.llm_score,
            } if gd.layer_scores else {},
            guardrail_scores = {"pii": gd.layer_scores.pii_score} if gd.layer_scores else {},
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
            detection_scores = {
                "rule": gd.layer_scores.rule_score,
                "ml":   gd.layer_scores.ml_score,
                "llm":  gd.layer_scores.llm_score,
            } if gd.layer_scores else {},
            guardrail_scores = {"pii": gd.layer_scores.pii_score} if gd.layer_scores else {},
            input_length     = len(scan_input),
    )

    # -- 12. Build OpenAI-compatible response --
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