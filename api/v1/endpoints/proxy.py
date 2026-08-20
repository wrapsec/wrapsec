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
import uuid
from dataclasses import dataclass

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
from domain.entities.request import RequestMetadata
from domain.enums import DetectionMode
from domain.value_objects.severity import compute_severity
from domain.value_objects.trace_id import TraceId
from engine.guardrails.output_guard import OutputGuard
from engine.guardrails.pii.redactor import PIIRedactor
from engine.proxy.router import (
    parse_model_string,
    resolve_provider,
    resolve_provider_from_dict,
)
from errors.catalog import ErrorCode
from errors.response import error_response as _catalog_error_response
from observability.metrics import record_proxy_request, record_request
from security.ip_allowlist import is_allowed
from services.gateway.fanout import (
    DetectionPolicy,
    ScanItem,
    charge_additional_units,
    scan_items,
)
from services.gateway.service import GatewayService
from services.policy_resolver import resolve_policy
from services.time import utc_now
from services.webhooks.emitter import emit_from_audit_background

router = APIRouter()
logger = logging.getLogger("wrapsec.proxy")

_gateway      = GatewayService()
_output_guard = OutputGuard()
_pii_redactor = PIIRedactor()

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

# Chat roles that get scanned, and the trust source each one carries.
#
# A caller controls the whole messages array, including what it labels as prior
# assistant output, so assistant text is treated as content of unknown origin
# rather than as something the caller authored. Both values are registered
# sources, so the trust tier comes from the source registry rather than from a
# judgement made here.
#
# system is excluded: system prompts are operator-controlled and routinely
# contain security wording that legitimately matches detectors. tool is excluded
# because tool-result security is handled elsewhere.
_ROLE_SOURCES = {
    "user":      "user_prompt",
    "assistant": "external_content",
}


@dataclass(frozen=True)
class MessageSegment:
    """One scannable message: where it sat, what it said, how far it is trusted."""

    index:  int
    role:   str
    text:   str
    source: str


def _message_text(message: dict) -> str:
    """
    Read a message's content as text.

    `content` is legally null for an assistant turn, and `.get(key, default)`
    returns None when the key is present with a null value rather than the
    default. Anything that is not a string becomes empty rather than reaching
    detection or string joins as a non-string.
    """
    content = message.get("content")
    return content if isinstance(content, str) else ""


def _eligible_segments(messages: list[dict], scan_all: bool) -> list[MessageSegment]:
    """
    Select the messages to scan, each carrying its own trust source.

    scan_all=False: the last eligible message only.
    scan_all=True:  every eligible message, in conversation order.

    Messages are NOT concatenated. A joined scan would force one trust
    classification onto content of differing origins, and would misreport
    provenance whichever source it chose.

    Raises ValueError when nothing scannable is present.
    """
    segments = [
        MessageSegment(
            index  = idx,
            role   = role,
            text   = text,
            source = _ROLE_SOURCES[role],
        )
        for idx, message in enumerate(messages)
        if (role := message.get("role")) in _ROLE_SOURCES
        and (text := _message_text(message))
    ]

    if not segments:
        raise ValueError("No scannable user or assistant message found in messages array.")

    return segments if scan_all else [segments[-1]]


# Strictness order used to reduce several message decisions to one. A request is
# only as safe as its worst message.
_DECISION_RANK = {"ALLOW": 0, "SANITIZE": 1, "BLOCK": 2}


def _strictest_index(results: list) -> int:
    """
    Index of the result that decides the request.

    Strictest decision wins; the higher risk score breaks a tie so the reported
    evidence matches the most severe finding rather than the first one seen.
    """
    def rank(pair):
        _idx, result = pair
        decision = result.decision
        return (
            _DECISION_RANK.get(decision.decision.value, 0),
            decision.risk_score.value,
        )

    return max(enumerate(results), key=rank)[0]


def _segment_audit_rows(segments: list[MessageSegment], scanned: list) -> list[dict]:
    """
    Per-message audit overlays, one per scanned message, in conversation order.

    Each row records what that specific message was judged to be and how far it
    was trusted, so the evidence behind an aggregate decision stays attributable
    to the message that produced it. The audit trace column is unique, so each
    row carries the id derived from the request trace and the message position.
    """
    rows = []
    for segment, (incoming, result) in zip(segments, scanned):
        decision = result.decision
        scores   = decision.layer_scores
        rows.append({
            "trace_id":         str(incoming.trace_id),
            "decision":         decision.decision.value,
            "risk_score":       decision.risk_score.value,
            "threats":          [threat.value for threat in decision.threats],
            "primary_reason":   decision.primary_reason or "NO_THREAT_DETECTED",
            "confidence":       decision.confidence if decision.confidence is not None else 0.0,
            "input_length":     len(segment.text),
            "input_source":     segment.source,
            "detection_scores": {
                "rule": scores.rule_score,
                "ml":   scores.ml_score,
                "llm":  scores.llm_score,
            } if scores else {},
            "guardrail_scores": {"pii": scores.pii_score} if scores else {},
        })
    return rows


def _apply_sanitized_segments(
    messages: list[dict],
    replacements: dict[int, str],
) -> list[dict]:
    """
    Rewrite each scanned message that came back sanitized, leaving the rest alone.

    Replacements are keyed by the message's position in the original array, so
    the rewrite lands on the message that was actually scanned. This applies to
    assistant messages as well as user ones: whatever was scanned is what gets
    forwarded, sanitized.

    Returns a new list; the caller's array is not mutated.
    """
    if not replacements:
        return messages

    messages = copy.deepcopy(messages)
    for index, text in replacements.items():
        if 0 <= index < len(messages):
            messages[index]["content"] = text
    return messages


# How an upstream failure is reported to the caller.
#
# Collapsing every provider failure into one status loses the only information
# the caller can act on: a rate limit needs a backoff, a model typo needs a fix
# in the request, and an operator credential problem is not an outage. The
# provider's own message is never echoed back, because it can carry provider
# account identifiers; it goes to the log with the trace id instead.
_PROVIDER_STATUS_MAP = {
    429: (429, "provider_rate_limited",    "The provider rate-limited this request."),
    401: (502, "provider_auth_failed",     "The provider rejected the configured credential."),
    403: (502, "provider_auth_failed",     "The provider rejected the configured credential."),
    404: (400, "provider_model_not_found", "The provider does not recognise the requested model."),
    400: (400, "provider_rejected_request", "The provider rejected the request payload."),
    422: (400, "provider_rejected_request", "The provider rejected the request payload."),
}


def _map_provider_failure(exc: Exception) -> tuple[int, str, str, str | None]:
    """
    Translate an upstream failure into (status, code, message, retry_after).

    retry_after is passed through only when the provider supplied it, so a
    caller backing off uses the provider's own guidance rather than a guess.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        upstream    = exc.response.status_code
        retry_after = exc.response.headers.get("retry-after")
        if upstream in _PROVIDER_STATUS_MAP:
            status, code, message = _PROVIDER_STATUS_MAP[upstream]
            return status, code, message, retry_after
        if upstream >= 500:
            return 502, "provider_unavailable", "The provider is currently unavailable.", retry_after
        return 502, "provider_unreachable", "The provider could not be reached.", retry_after

    return 502, "provider_unreachable", "The provider could not be reached.", None


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


async def _record_allowlist_denial(
    db,
    request,
    ip_address: str | None,
    user_agent: str | None,
) -> None:
    """
    Record a credential used from an unapproved network.

    Lands with the other credential-level events rather than in the request
    audit trail: nothing was scanned and no decision was made, so recording it
    as a security decision would misreport what happened.

    A failure to record must not become a failure to deny, so the write is
    best-effort and the denial stands either way.
    """
    try:
        from db.models import AuthEventModel

        tenant_id = getattr(request.state, "tenant_id", None)
        db.add(AuthEventModel(
            tenant_id      = uuid.UUID(tenant_id) if tenant_id else None,
            user_id        = None,
            action         = "api_key_ip_denied",
            success        = False,
            failure_reason = "ip_not_allowed",
            ip_address     = ip_address,
            user_agent     = (user_agent or "")[:500] or None,
        ))
        await db.commit()
    except Exception as exc:
        logger.error("Could not record a source-network denial: %s", exc)


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
    # Tenant attribution -- without these the proxy audit row is NULL-tenant, so
    # it drops out of tenant-scoped /v1/audit/logs and out of the per-tenant
    # tamper-evident hash chain.
    tenant_id:        str | None = None,
    dept_id:          str | None = None,
    app_id:           str | None = None,
    source:           str | None = None,
    ip_address:       str | None = None,
    user_agent:       str | None = None,
    # Per-message evidence, one entry per scanned message. When absent a
    # single row is written from the aggregate fields above.
    segment_rows:     list[dict] | None = None,
    input_scan_ms:    int | None = None,
    output_scan_ms:   int | None = None,
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
        elif mode == "full":
            stored_input_raw        = input_raw
            stored_input_sanitized  = input_sanitized
            stored_output_raw       = output_raw
            stored_output_sanitized = output_sanitized
        else:
            # "masked" and -- critically -- any unrecognized value fail CLOSED:
            # never store raw prompt/response on a misconfigured mode. Only an
            # explicit "full" opts into plaintext retention.
            if mode != "masked":
                logger.warning(
                    "unrecognized data_storage_mode=%r; defaulting to masked", mode
                )
            stored_input_raw        = None
            stored_input_sanitized  = input_sanitized
            stored_output_raw       = None
            stored_output_sanitized = output_sanitized

        # 1. Insert into proxy_interactions
        interaction = ProxyInteractionModel(
            trace_id              = trace_id,
            key_id                = key_id,
            tenant_id             = uuid.UUID(tenant_id) if tenant_id else None,
            dept_id               = uuid.UUID(dept_id)   if dept_id   else None,
            app_id                = uuid.UUID(app_id)    if app_id    else None,
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
            input_scan_ms         = input_scan_ms,
            output_scan_ms        = output_scan_ms,
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

        # 2. Insert audit_logs rows, all linked to the interaction above.
        #
        # One row per scanned message when the caller supplied per-message
        # evidence, so the reason for a decision stays attributable to the
        # message that caused it. The interaction row above carries the
        # aggregate. Rows are written in order, not concurrently: the audit
        # chain is per-tenant and each row hashes the previous one.
        repo = AuditRepository(db)
        rows = segment_rows or [{
            "trace_id":         trace_id,
            "decision":         input_decision,
            "risk_score":       risk_score,
            "threats":          input_threats or [],
            "primary_reason":   input_reason,
            "confidence":       input_confidence,
            "input_length":     input_length,
            "detection_scores": detection_scores or {},
            "guardrail_scores": guardrail_scores or {},
        }]

        for row in rows:
            row_trace = row["trace_id"]
            row_conf  = row["confidence"]
            audit_row = {
                "trace_id":              row_trace,
                "decision":              row["decision"],
                "risk_score":            row["risk_score"],
                "threats":               row["threats"],
                "input_hash":            "proxy:" + row_trace,
                "detection_mode":        "fast",
                "execution_mode":        "proxy",
                "llm_invoked":           False,
                "latency_ms":            float(total_latency_ms),
                "detection_scores":      row["detection_scores"],
                "guardrail_scores":      row["guardrail_scores"],
                "key_id":                key_id,
                "primary_reason":        row["primary_reason"],
                "confidence":            row_conf,
                "confidence_band":       "HIGH" if row_conf >= 0.7 else "MEDIUM" if row_conf >= 0.4 else "LOW",
                "input_length":          row["input_length"],
                "tenant_id":             tenant_id,
                "dept_id":               dept_id,
                "app_id":                app_id,
                "source":                source,
                "ip_address":            ip_address,
                "user_agent":            user_agent,
                "severity":              compute_severity(
                    decision       = row["decision"],
                    risk_score     = row["risk_score"],
                    primary_reason = row["primary_reason"],
                ),
                "proxy_interaction_id":  interaction.id,
            }
            if "input_source" in row:
                audit_row["input_source"] = row["input_source"]
            await repo.create(audit_row)

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
    Auth: a valid live API key only (trial keys and dashboard sessions are rejected).
    """
    # 2.3 (M5 pt3): the proxy is API-key-only, matching the docstring. A dashboard
    # (JWT/user) principal is rejected here. If a playground is ever wanted it must
    # opt in ADMIN/DEVELOPER JWT deliberately -- never VIEWER by accident.
    if getattr(request.state, "principal_type", None) == "user":
        return _catalog_error_response(
            ErrorCode.PROXY_REQUIRES_API_KEY,
            trace_id=getattr(request.state, "trace_id", "") or "",
        )

    wall_start = time.monotonic()
    trace_id   = str(TraceId.generate())
    key_id     = getattr(request.state, "key_id",    None)
    tenant_id  = getattr(request.state, "tenant_id", None)
    dept_id    = getattr(request.state, "dept_id",    None)
    app_id     = getattr(request.state, "app_id",     None)
    source     = getattr(request.state, "key_name",   None) or "proxy"
    ip_address = getattr(request.state, "ip_address", None)
    user_agent = getattr(request.state, "user_agent", None)

    # -- 0a. Source network check --
    # Runs before every other check so a credential used from an unapproved
    # network costs nothing: no policy resolution, no detection, no upstream
    # call. The address comes from get_client_ip, which only believes a
    # forwarded header when the immediate peer is a configured trusted proxy,
    # so a caller cannot present an approved address by claiming one.
    _allowlist = getattr(request.state, "ip_allowlist", None)
    if _allowlist and not is_allowed(ip_address, _allowlist):
        logger.warning(
            "Source network denied trace_id=%s key=%s ip=%s",
            trace_id, key_id, ip_address,
        )
        await _record_allowlist_denial(db, request, ip_address, user_agent)
        return _error_response(
            status_code  = 403,
            message      = "This credential is not permitted from your network address.",
            error_type   = "forbidden",
            error_code   = "ip_not_allowed",
            wrapsec_meta = {"trace_id": trace_id},
            headers      = {"X-WrapSec-Trace-Id": trace_id},
        )

    # -- 0. Trial key check - proxy mode not available for trial keys --
    key_type = getattr(request.state, "key_type", "live")
    if key_type == "trial":
        return _error_response(
            status_code  = 403,
            message      = "Proxy mode is not available for trial keys. Upgrade to a live key.",
            error_type   = "forbidden",
            error_code   = "trial_proxy_disabled",
            wrapsec_meta = {"trace_id": trace_id},
            headers      = {"X-WrapSec-Trace-Id": trace_id},
        )

    # -- 1. Parse model string if provided; deferred resolution happens after step 3 --
    provider_name, model_name = None, None
    if body.model is not None:
        try:
            provider_name, model_name = parse_model_string(body.model)
        except ValueError as exc:
            return _error_response(
                status_code  = 400,
                message      = str(exc),
                error_type   = "invalid_request_error",
                error_code   = "invalid_model_format",
                wrapsec_meta = {"trace_id": trace_id},
                headers      = {"X-WrapSec-Trace-Id": trace_id},
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
        return _error_response(
            status_code  = 400,
            message      = (
                        "No proxy provider configured for this API key or department. "
                        "Configure a provider via PUT /v1/settings/proxy or the department policy."
                    ),
            error_type   = "invalid_request_error",
            error_code   = "proxy_not_configured",
            wrapsec_meta = {"trace_id": trace_id},
            headers      = {"X-WrapSec-Trace-Id": trace_id},
        )

    # -- 3b. Resolve model from default_model if not supplied in request --
    if provider_name is None:
        default_model = (
            config.default_model if config
            else (dept_proxy_cfg or {}).get("default_model")
        )
        if not default_model:
            return _error_response(
                status_code  = 400,
                message      = (
                            "No model specified and no default_model configured. "
                            "Pass 'model' in the request body or set a default_model in proxy settings."
                        ),
                error_type   = "invalid_request_error",
                error_code   = "model_required",
                wrapsec_meta = {"trace_id": trace_id},
                headers      = {"X-WrapSec-Trace-Id": trace_id},
            )
        try:
            provider_name, model_name = parse_model_string(default_model)
        except ValueError as exc:
            return _error_response(
                status_code  = 400,
                message      = str(exc),
                error_type   = "invalid_request_error",
                error_code   = "invalid_model_format",
                wrapsec_meta = {"trace_id": trace_id},
                headers      = {"X-WrapSec-Trace-Id": trace_id},
            )

    # -- 3c. Reject a provider the tenant has not configured --
    # The request names the provider; the credential and endpoint come from the
    # stored configuration. Honouring a request for a different provider would
    # build that provider's adapter around another provider's endpoint, so the
    # call fails upstream in a way that reads as an outage rather than as the
    # configuration error it is. Checked here, before any scanning or upstream
    # work, so a misconfigured request costs nothing.
    _configured_provider = (
        config.provider if config else (dept_proxy_cfg or {}).get("provider")
    )
    if _configured_provider and provider_name and provider_name != _configured_provider:
        logger.warning(
            "Provider mismatch trace_id=%s requested=%s configured=%s",
            trace_id, provider_name, _configured_provider,
        )
        return _error_response(
            status_code  = 400,
            message      = (
                f"This deployment is configured for the '{_configured_provider}' provider, "
                f"but the request asked for '{provider_name}'. Use a "
                f"'{_configured_provider}/<model>' model string, or update the proxy "
                f"provider configuration."
            ),
            error_type   = "invalid_request_error",
            error_code   = "provider_mismatch",
            wrapsec_meta = {"trace_id": trace_id},
            headers      = {"X-WrapSec-Trace-Id": trace_id},
        )

    # -- 4. Read WrapSec request headers --
    scan_all = request.headers.get("X-WrapSec-Scan-All-Messages", "false").lower() == "true"
    mode     = request.headers.get("X-WrapSec-Mode", "fast").lower()
    inline   = request.headers.get("X-WrapSec-Inline-Meta", "false").lower() == "true"

    if mode not in ("fast", "full"):
        mode = "fast"

    # -- 5. Select the messages to scan --
    try:
        segments = _eligible_segments(body.messages, scan_all)
    except ValueError as exc:
        return _error_response(
            status_code  = 400,
            message      = str(exc),
            error_type   = "invalid_request_error",
            error_code   = "invalid_messages",
            wrapsec_meta = {"trace_id": trace_id},
            headers      = {"X-WrapSec-Trace-Id": trace_id},
        )

    # Bound the fan-out. Each scanned message costs a detection run and an audit
    # chain append, so a long conversation must not turn one request into
    # unbounded work. Reject rather than truncate: silently scanning part of a
    # conversation would report a decision that did not cover what was sent.
    _max_messages = get_settings().max_scan_all_messages
    if len(segments) > _max_messages:
        return _error_response(
            status_code  = 400,
            message      = (
                        f"Scanning all messages is limited to {_max_messages} eligible "
                        f"messages per request; this request has {len(segments)}. "
                        f"Send fewer messages or omit the scan-all header."
                    ),
            error_type   = "invalid_request_error",
            error_code   = "too_many_messages",
            wrapsec_meta = {"trace_id": trace_id},
            headers      = {"X-WrapSec-Trace-Id": trace_id},
        )

    # Charge the extra detection units this request consumes. One unit was
    # already taken by the HTTP request itself.
    await charge_additional_units(request, len(segments))

    # -- 6. Scan every selected message, then reduce to one decision --
    # Each message is scanned on its own so it carries its own trust source; a
    # joined scan would force one classification onto content of mixed origin.
    # The audit trace column is unique, so each scan gets an id derived from the
    # request trace and the message's position. The response header keeps the
    # request-level id.
    pii_policy      = policy.get("guardrails", {}).get("pii", {})
    toxicity_policy = policy.get("guardrails", {}).get("toxicity", {})

    _scan_start = time.monotonic()
    scanned = await scan_items(
        [
            ScanItem(
                input        = segment.text,
                input_source = segment.source,
                trace_id     = f"{trace_id}-{segment.index}",
            )
            for segment in segments
        ],
        gateway        = _gateway,
        policy         = DetectionPolicy(
            block_threshold             = policy["thresholds"]["block"],
            sanitize_threshold          = policy["thresholds"]["sanitize"],
            pii_block_threshold         = pii_policy.get("block_threshold"),
            pii_sanitize_threshold      = pii_policy.get("sanitize_threshold"),
            toxicity_block_threshold    = toxicity_policy.get("block_threshold"),
            toxicity_sanitize_threshold = toxicity_policy.get("sanitize_threshold"),
            rule_enabled                = policy["detection"]["rule_enabled"],
            ml_enabled                  = policy["detection"]["ml_enabled"],
            llm_enabled                 = policy["detection"]["llm_enabled"] if mode == "full" else False,
            llm_settings                = policy["llm"],
        ),
        detection_mode = DetectionMode(mode),
        metadata       = RequestMetadata(
            tenant_id = getattr(request.state, "tenant_id", None),
            user_id   = None,
        ),
    )

    _input_scan_ms = int((time.monotonic() - _scan_start) * 1000)

    _results       = [result for _incoming, result in scanned]
    _winner        = _strictest_index(_results)
    gateway_result = _results[_winner]
    # The audit row records the text that produced the decision.
    scan_input     = segments[_winner].text
    # Per-message evidence, written as one audit row per scanned message.
    _audit_rows    = _segment_audit_rows(segments, scanned)

    gd             = gateway_result.decision
    input_decision = gd.decision.value          # ALLOW / BLOCK / SANITIZE
    input_reason   = gd.primary_reason if gd.primary_reason is not None else "NO_THREAT_DETECTED"
    input_conf     = gd.confidence if gd.confidence is not None else 0.0
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
            segment_rows=_audit_rows,
            input_scan_ms=_input_scan_ms,
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            tenant_id=tenant_id, dept_id=dept_id, app_id=app_id,
            source=source, ip_address=ip_address, user_agent=user_agent,
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
    # Every scanned message that came back sanitized is rewritten in place, not
    # just the one that decided the request: each was scanned independently, so
    # each may carry its own redactions.
    messages = _apply_sanitized_segments(
        body.messages,
        {
            segment.index: result.decision.sanitized_input
            for segment, (_incoming, result) in zip(segments, scanned)
            if result.decision.sanitized_input
        },
    )

    # -- 8. Resolve provider and forward request --
    try:
        if config:
            provider_instance, _ = resolve_provider(provider_name, config)
        else:
            if dept_proxy_cfg is None:
                raise ValueError("no proxy provider configured")
            provider_instance, _ = resolve_provider_from_dict(provider_name, dept_proxy_cfg)
    except ValueError as exc:
        total_ms = int((time.monotonic() - wall_start) * 1000)
        logger.error("Provider resolution failed trace_id=%s: %s", trace_id, exc)
        return _error_response(
            status_code  = 500,
            message      = "Provider configuration error.",
            error_type   = "provider_error",
            error_code   = "provider_config_error",
            wrapsec_meta = {"trace_id": trace_id},
            headers      = {"X-WrapSec-Trace-Id": trace_id},
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

    assert model_name is not None
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
            segment_rows=_audit_rows,
            input_scan_ms=_input_scan_ms,
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            tenant_id=tenant_id, dept_id=dept_id, app_id=app_id,
            source=source, ip_address=ip_address, user_agent=user_agent,
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

    except (KeyError, IndexError, TypeError, ValueError) as exc:
        # The provider answered, but not in a shape that can be parsed. Treated
        # as an upstream failure rather than an internal error: nothing is
        # released to the caller, because the guard cannot inspect what cannot
        # be read.
        total_ms = int((time.monotonic() - wall_start) * 1000)
        logger.error("Malformed provider response trace_id=%s: %.500s", trace_id, exc)
        headers  = _build_wrapsec_headers(
            trace_id, input_decision, input_reason, input_conf,
            input_decision == "SANITIZE", None, False, STATUS_FAILED,
            provider_name, model_name, total_ms,
        )
        await _log_interaction(
            segment_rows=_audit_rows,
            input_scan_ms=_input_scan_ms,
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            tenant_id=tenant_id, dept_id=dept_id, app_id=app_id,
            source=source, ip_address=ip_address, user_agent=user_agent,
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
            message      = (
                "The provider returned a malformed response. Your request passed "
                "security validation but could not be completed."
            ),
            error_type   = "provider_error",
            error_code   = "provider_malformed_response",
            wrapsec_meta = {
                "trace_id":         trace_id,
                "decision":         input_decision,
                "execution_status": STATUS_FAILED,
            },
            headers=headers,
        )

    except (httpx.ConnectError, httpx.HTTPStatusError) as exc:
        total_ms = int((time.monotonic() - wall_start) * 1000)
        _status, _code, _message, _retry_after = _map_provider_failure(exc)
        logger.error(
            "Provider call failed trace_id=%s code=%s: %.500s",
            trace_id, _code, exc,
        )
        headers  = _build_wrapsec_headers(
            trace_id, input_decision, input_reason, input_conf,
            input_decision == "SANITIZE", None, False, STATUS_FAILED,
            provider_name, model_name, total_ms,
        )
        await _log_interaction(
            segment_rows=_audit_rows,
            input_scan_ms=_input_scan_ms,
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            tenant_id=tenant_id, dept_id=dept_id, app_id=app_id,
            source=source, ip_address=ip_address, user_agent=user_agent,
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
        if _retry_after:
            headers["Retry-After"] = _retry_after
        return _error_response(
            status_code  = _status,
            message      = f"{_message} Your request passed security validation but could not be completed.",
            error_type   = "provider_error",
            error_code   = _code,
            wrapsec_meta = {
                "trace_id":         trace_id,
                "decision":         input_decision,
                "execution_status": STATUS_FAILED,
            },
            headers=headers,
        )

    # -- 9. Run OutputGuard on provider response --
    # The guard inspects text. A response whose content is not text -- a
    # tool-call reply carries a null content alongside the call -- cannot be
    # inspected, and forwarding it unchecked would hand the caller output that
    # never passed the guard. Native tool calling is not supported, so this is
    # refused rather than partially honoured.
    if not isinstance(provider_response.content, str):
        total_ms = int((time.monotonic() - wall_start) * 1000)
        logger.error(
            "Provider returned an uninspectable response trace_id=%s type=%s",
            trace_id, type(provider_response.content).__name__,
        )
        headers = _build_wrapsec_headers(
            trace_id, input_decision, input_reason, input_conf,
            input_decision == "SANITIZE", None, False, STATUS_FAILED,
            provider_name, model_name, total_ms,
        )
        await _log_interaction(
            segment_rows=_audit_rows,
            input_scan_ms=_input_scan_ms,
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            tenant_id=tenant_id, dept_id=dept_id, app_id=app_id,
            source=source, ip_address=ip_address, user_agent=user_agent,
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
            message      = (
                "The provider returned a response shape this endpoint does not support, "
                "so it could not be security-checked and was not forwarded."
            ),
            error_type   = "provider_error",
            error_code   = "provider_response_unsupported",
            wrapsec_meta = {
                "trace_id":         trace_id,
                "decision":         input_decision,
                "execution_status": STATUS_FAILED,
            },
            headers=headers,
        )

    _guard_start      = time.monotonic()
    output_result     = _output_guard.inspect(provider_response.content)
    _output_scan_ms   = int((time.monotonic() - _guard_start) * 1000)
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
            segment_rows=_audit_rows,
            input_scan_ms=_input_scan_ms,
            output_scan_ms=_output_scan_ms,
            db=db, trace_id=trace_id, key_id=key_id, user_id=None,
            tenant_id=tenant_id, dept_id=dept_id, app_id=app_id,
            source=source, ip_address=ip_address, user_agent=user_agent,
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
        segment_rows=_audit_rows,
        input_scan_ms=_input_scan_ms,
        output_scan_ms=_output_scan_ms,
        db=db, trace_id=trace_id, key_id=key_id, user_id=None,
        tenant_id=tenant_id, dept_id=dept_id, app_id=app_id,
        source=source, ip_address=ip_address, user_agent=user_agent,
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

    # Pass the provider's own token counts through when it sent them. This is
    # observability, not metering: the numbers are reported as received and
    # nothing here prices, budgets, or bills against them. Absent when the
    # provider omits it, so a caller must treat it as optional.
    _usage = provider_response.raw.get("usage") if isinstance(provider_response.raw, dict) else None
    if isinstance(_usage, dict):
        response_body["usage"] = _usage

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
