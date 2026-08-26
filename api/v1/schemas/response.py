# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Response models for the published API contract.

These describe what the API ALREADY returns. They were written from measured
responses -- the recorded baselines in `tests/integration/snapshots/` and the
handlers that build them -- not from documentation, and adding one must not
change a single byte on the wire.

ABSENCE IS PART OF THE CONTRACT, and it is not the same thing as null. Three
fields are absent rather than null when they do not apply, and one of them is a
security boundary:

  * `layers[].score` is ABSENT for a caller without `settings:read`. A null
    would leak that a score exists and was withheld, and would force every
    client to distinguish "no score" from "score is 0.0";
  * `sanitized_input` and `output` appear only when the pipeline produced them;
  * `assessment.posture` appears only when provenance shifted the thresholds.

Meanwhile several fields are legitimately NULL and must stay null: a scan that
reached no reason has `primary_reason: null`, and a batch where nothing scored
above zero has `highest_risk_item: null`. Callers already read those keys.

The mechanism for that distinction is `response_model_exclude_unset=True` on the
route, with the optional fields defaulting to None. A key the handler did not put
in the dict is unset and is dropped; a key it set to None is set and is kept. It
is deliberately NOT `response_model_exclude_none`, which cannot tell the two
apart and would turn every legitimate null into an absence.

What the models add, given they change no bytes: undeclared fields are dropped
before serialization, so a field added to an internal structure cannot reach a
caller by accident, and the schema in `docs/openapi.json` becomes the generated
truth rather than an empty object.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ── the canonical error envelope ─────────────────────────────────────────────
# One shape for every WrapSec error, built by `errors/response.py`. Declared here
# so routes can reference it in `responses={...}`; it is not per-endpoint, and a
# family must never define its own. The OpenAI-compatible envelope on
# `/v1/chat/completions` is a separate protocol shape and is not modelled here.


class ErrorDetail(BaseModel):
    code:     str = Field(description="Stable machine-readable error code from the catalog.")
    severity: str = Field(description="Catalog severity: INFO, WARNING, ERROR or CRITICAL.")
    key:      str = Field(description="Localization key; clients may resolve their own text from it.")
    params:   dict[str, Any] = Field(description="Values interpolated into the localized message.")
    message:  str = Field(description="English message. Localized clients should prefer key + params.")
    trace_id: str = Field(description="Correlates the failure with the audit trail.")
    invalid_params: list[dict[str, Any]] | None = Field(
        default     = None,
        description = "Per-field detail, present only on validation failures.",
    )


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


# ── the security assessment, shared by the scan and batch responses ──────────


class AssessmentLayer(BaseModel):
    """One detector's contribution.

    `score` is omitted -- not nulled -- for a caller that does not hold
    `settings:read`, or for any trial key. `name` and `decision` are always
    present, so a restricted caller still sees which layer landed in which
    bucket.
    """

    name:     str = Field(description="Detector name, for example `rule_score` or `ml_score`.")
    decision: str = Field(description="This layer's classification: ALLOW, SANITIZE or BLOCK.")
    score:    float | None = Field(
        default     = None,
        description = "0.0-1.0 contribution. Absent when the caller may not read layer scores.",
    )


class Assessment(BaseModel):
    """The self-contained verdict. Agents and the protocol adapter consume this
    object; the flat top-level fields duplicate part of it for compatibility."""

    decision:        str = Field(description="ALLOW, SANITIZE or BLOCK.")
    risk_score:      float = Field(description="Aggregate risk, 0.0-1.0.")
    risk_level:      str = Field(description="Banded risk: NONE, LOW, MEDIUM, HIGH or CRITICAL.")
    primary_reason:  str | None = Field(description="Dominant reason for the decision, null if none applied.")
    confidence:      float | None = Field(description="Confidence in the decision, 0.0-1.0.")
    confidence_band: str | None = Field(description="LOW, MEDIUM or HIGH.")
    threats:         list[str] = Field(description="Threat categories detected.")
    layers:          list[AssessmentLayer] = Field(description="Per-detector contributions.")
    posture:         dict[str, Any] | None = Field(
        default     = None,
        description = "Source-aware threshold shift. Absent unless provenance changed the posture.",
    )


# ── POST /v1/ai/request ──────────────────────────────────────────────────────


class ScanProcessing(BaseModel):
    latency_ms:     float = Field(description="Detection time in milliseconds.")
    llm_invoked:    bool = Field(description="Whether the LLM detector ran.")
    detection_mode: str = Field(description="fast, balanced or thorough.")
    execution_mode: str = Field(description="scan_only or proxy.")


class ScanDebug(BaseModel):
    """Admin-only diagnostics. Present only when an admin key sets
    `options.debug`, and never cached."""

    rule_score:      float
    ml_score:        float
    llm_score:       float
    pii_score:       float
    layer_decisions: dict[str, str]


class ScanResponse(BaseModel):
    trace_id:             str = Field(description="Identifier for this scan; reads back via GET /v1/ai/requests/{trace_id}.")
    decision:             str = Field(description="ALLOW, SANITIZE or BLOCK.")
    decision_version:     str = Field(description="Version of the decision contract.")
    risk_score:           float = Field(description="Aggregate risk, 0.0-1.0.")
    primary_reason:       str | None = Field(description="Dominant reason, null if none applied.")
    confidence:           float | None = Field(description="Confidence in the decision, 0.0-1.0.")
    confidence_band:      str | None = Field(description="LOW, MEDIUM or HIGH.")
    threats:              list[str] = Field(description="Threat categories detected.")
    sanitization_applied: bool = Field(description="True only when the input text was actually rewritten.")
    processing:           ScanProcessing
    assessment:           Assessment

    sanitized_input: str | None = Field(
        default     = None,
        description = "Rewritten input. Present only when the text was redacted; forward this instead of the original.",
    )
    output: str | None = Field(
        default     = None,
        description = "Model output. Present only in proxy execution mode.",
    )
    debug: ScanDebug | None = Field(
        default     = None,
        description = "Admin-only detector diagnostics. Present only when requested by an admin key.",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "trace_id":             "req_2c31dee1bfda40a0b178c932d659f039",
                "decision":             "ALLOW",
                "decision_version":     "v1.0",
                "risk_score":           0.0,
                "primary_reason":       "NO_THREAT_DETECTED",
                "confidence":           1.0,
                "confidence_band":      "HIGH",
                "threats":              [],
                "sanitization_applied": False,
                "processing": {
                    "latency_ms":     41.2,
                    "llm_invoked":    False,
                    "detection_mode": "fast",
                    "execution_mode": "scan_only",
                },
                "assessment": {
                    "decision":        "ALLOW",
                    "risk_score":      0.0,
                    "risk_level":      "NONE",
                    "primary_reason":  "NO_THREAT_DETECTED",
                    "confidence":      1.0,
                    "confidence_band": "HIGH",
                    "threats":         [],
                    "layers": [
                        {"name": "rule_score", "score": 0.0, "decision": "ALLOW"},
                        {"name": "ml_score",   "score": 0.0, "decision": "ALLOW"},
                    ],
                },
            }
        }
    }


# ── POST /v1/ai/scan-batch ───────────────────────────────────────────────────


class BatchSummary(BaseModel):
    blocked:           int = Field(description="Items decided BLOCK.")
    sanitized:         int = Field(description="Items decided SANITIZE.")
    allowed:           int = Field(description="Items decided ALLOW.")
    highest_risk:      float = Field(description="Highest risk score across the batch.")
    highest_risk_item: str | None = Field(
        description="Caller-supplied id of the riskiest item. Null when no item scored above zero, "
                    "and null when the riskiest item carried no id.",
    )
    threats:           list[str] = Field(description="Union of threat categories across the batch, sorted.")


class BatchItemResult(BaseModel):
    id:         str | None = Field(description="The caller's own reference for this item, echoed back. Null if none was sent.")
    trace_id:   str = Field(description="Identifier for this item's scan; each item is audited independently.")
    decision:   str = Field(description="ALLOW, SANITIZE or BLOCK.")
    assessment: Assessment


class ScanBatchResponse(BaseModel):
    count:   int = Field(description="Number of items scanned.")
    summary: BatchSummary
    results: list[BatchItemResult] = Field(description="One result per item, in request order.")


# ── health and capabilities ──────────────────────────────────────────────────


class HealthResponse(BaseModel):
    """Unauthenticated liveness plus build identity."""

    status:  str = Field(description="Always `ok` -- reaching this endpoint at all is the signal.")
    version: str = Field(description="Running build. Deliberately unauthenticated: it is how a deployment is verified.")


class LivenessResponse(BaseModel):
    status: str = Field(description="Always `alive`. The process answered; nothing else is checked.")


class HealthChecks(BaseModel):
    """Per-component status. `ok` / `unavailable` for infrastructure,
    `healthy` / `degraded` / `unavailable` for the detector tiers."""

    database:             str
    redis:                str
    tfidf_detector:       str = Field(description="Tier 1, REQUIRED. Degraded here means the instance refuses traffic fail-closed.")
    transformer_detector: str = Field(description="Tier 2, OPTIONAL. Degraded on a default build and does not affect the status code.")


class ReadinessResponse(BaseModel):
    """Readiness. The STATUS CODE is the contract and the body is the detail --
    an orchestrator routes on the code.

    The same body shape is returned with 200 and with 503, so one model
    describes both. `status: degraded` with 200 means serving with less signal
    (Tier 2 absent); 503 means a required component is down.
    """

    status: str = Field(description="`ready` when every check passed, `degraded` when any did not.")
    checks: HealthChecks


class ConfigThresholds(BaseModel):
    """`source` always; the values only for a caller holding `settings:read`.

    The restricted form is the same object with the numbers ABSENT, not nulled:
    a null would still confirm a threshold exists and is being withheld, and the
    point of the restriction is that a caller cannot calibrate against it.
    """

    source:   str = Field(description="`database` when stored for this tenant, `environment` otherwise.")
    block:    float | None = Field(default=None, description="Absent without `settings:read`.")
    sanitize: float | None = Field(default=None, description="Absent without `settings:read`.")


class ConfigDetectionLayers(BaseModel):
    source: str
    rule:   bool | None = Field(default=None, description="Absent without `settings:read`.")
    ml:     bool | None = Field(default=None, description="Absent without `settings:read`.")
    llm:    bool | None = Field(default=None, description="Absent without `settings:read`.")


class ConfigLLM(BaseModel):
    source:      str
    provider:    str | None = Field(default=None, description="Absent without `settings:read`.")
    model:       str | None = Field(default=None, description="Absent without `settings:read`.")
    llm_trigger: float | None = Field(default=None, description="Absent without `settings:read`.")
    timeout:     int | None = Field(default=None, description="Absent without `settings:read`.")


class ConfigRateLimit(BaseModel):
    source:     str
    per_minute: int | None = Field(default=None, description="Absent without `settings:read`.")


class HealthConfigResponse(BaseModel):
    """The configuration in force, for deployment verification.

    Every caller gets the same TOP-LEVEL keys; the difference is inside each
    section. A caller without `settings:read` -- VIEWER, or any trial key -- sees
    each section reduced to its `source` marker, which says whether configuration
    was customised without saying what it was set to. No provider credential is
    ever included, for any caller.
    """

    version:          str
    thresholds:       ConfigThresholds
    detection_layers: ConfigDetectionLayers
    llm:              ConfigLLM
    rate_limit:       ConfigRateLimit


class CapabilitiesResponse(BaseModel):
    """Which optional plugin capabilities are effective in this DEPLOYMENT.

    Process-global, not per tenant, and informational only -- never an
    authorization control. The OSS build returns an empty list and `oss`.
    """

    edition:      str = Field(description="`oss` with no capabilities registered, `enterprise` otherwise. Display metadata, not a claim.")
    capabilities: list[str] = Field(description="Effective capability names; empty on the OSS build.")


# ── the proxy interaction read-back ──────────────────────────────────────────
#
# `_serialize` in `api/v1/endpoints/proxy_interactions.py` builds both bodies:
# the LIST item, and the DETAIL item which is the same projection plus the four
# raw/sanitized text fields. Modelled as base + subclass rather than one model
# with four optional fields, deliberately: an optional field would appear in the
# LIST schema, telling a consumer that prompt and completion text might come back
# from a listing. It cannot -- `detail=True` is only ever passed on the
# single-record route -- and the schema should not suggest otherwise.
#
# Nothing here is conditionally absent within a given route: every key is set on
# every row, and the empty ones are null.


class ProxyInteraction(BaseModel):
    """One proxied request, as persisted. The list projection."""

    id:                   str = Field(description="Row identifier.")
    trace_id:             str = Field(description="Correlates with the audit trail.")
    created_at:           str | None = Field(description="ISO-8601 UTC with a Z suffix.")
    key_id:               str | None = Field(description="Owning API key, with the internal `key:` prefix stripped. Null for a system record.")
    user_id:              str | None
    input_decision:       str = Field(description="Verdict on the prompt: ALLOW, SANITIZE or BLOCK.")
    input_primary_reason: str
    input_confidence:     float
    input_threats:        list[str]
    input_attack_type:    str | None
    provider:             str | None = Field(description="Null when the request never reached a provider.")
    model:                str | None
    provider_latency_ms:  int | None = Field(description="Provider time only. Null when no call was made.")
    execution_status:     str = Field(description="How the proxied call ended, for example `completed`.")
    output_decision:      str | None = Field(description="Verdict on the reply. Null when there was no reply to guard.")
    output_primary_reason: str | None
    output_confidence:    float | None
    output_threats:       list[str]
    behavior_flag:        str | None
    output_flags:         Any | None
    total_latency_ms:     int = Field(description="End to end, including detection.")


class ProxyInteractionDetail(ProxyInteraction):
    """The single-record projection: everything above plus the stored text.

    These four fields are the reason this route is scoped to the interaction's
    owner. They are returned exactly as persisted -- this model describes that
    and does not add, redact or reshape anything.
    """

    input_raw:        str | None = Field(description="Prompt as received. Null when storage mode did not retain it.")
    input_sanitized:  str | None = Field(description="Prompt after redaction. Null when nothing was rewritten.")
    output_raw:       str | None = Field(description="Provider reply as received.")
    output_sanitized: str | None = Field(description="Reply after redaction.")


class ProxyInteractionsResponse(BaseModel):
    """A page of proxy interactions, newest first.

    Unlike the audit page, this one echoes `limit` and `offset` back, and both
    are CLAMPED by the handler (limit to 1-200, offset to >= 0) -- so the values
    returned are the ones actually applied, not the ones requested.
    """

    total:  int = Field(description="Matching rows across all pages.")
    limit:  int = Field(description="Page size actually applied after clamping.")
    offset: int = Field(description="Offset actually applied after clamping.")
    items:  list[ProxyInteraction] = Field(description="Newest first; empty when nothing matched.")


# ── the public API-key routes ────────────────────────────────────────────────
#
# TWO models, not one. Creation and listing return genuinely different bodies,
# and the difference is a credential: `POST /v1/keys` returns the raw key ONCE,
# at creation, and it can never be retrieved again. `GET /v1/keys` returns
# metadata only.
#
# Merging them behind one permissive model would put `api_key` in the LIST
# schema as an optional field -- advertising that a listing might return
# credentials. It does not, it must not, and the schema should not leave the
# question open. So the secret is declared on the creation model alone, and
# nothing in the list model can carry it.
#
# Neither model declares `key_hash`, `is_admin`, `revoked`, `ip_allowlist` or the
# row id. Those are stored, and the endpoints do not return them; the models
# describe the responses, not the table.


class ApiKeyCreated(BaseModel):
    """The one response in the API that carries a credential.

    `api_key` is the raw key, returned exactly once. It is not stored in
    recoverable form -- only a hash is persisted -- so a caller that loses it
    must create another key.
    """

    key_id:     str = Field(description="Stable identifier for this key. Safe to log and to display.")
    name:       str
    api_key:    str = Field(description="The raw key. Returned ONLY here, only at creation, and never again.")
    key_type:   str = Field(description="`live` or `trial`.")
    app_id:     str | None = Field(description="Set when the key is application-scoped.")
    dept_id:    str | None = Field(description="Owning department. Creation requires one, directly or derived from the application.")
    tenant_id:  str | None
    created_at: str = Field(description="ISO-8601 UTC with a Z suffix.")
    expires_at: str | None = Field(description="Null when the key does not expire.")


class ApiKeyListItem(BaseModel):
    """A key as listed. Metadata only -- no credential, no hash.

    Carries three fields creation does not: the resolved department and
    application names, and `last_used_at`.
    """

    key_id:       str
    name:         str
    app_id:       str | None
    dept_id:      str | None
    dept_name:    str | None = Field(description="Resolved name; null when the department no longer exists.")
    app_name:     str | None = Field(description="Resolved name; null when the application no longer exists.")
    key_type:     str = Field(description="`live` or `trial`; defaults to `live` for a row that predates the column.")
    created_at:   str
    expires_at:   str | None
    last_used_at: str | None = Field(description="Null until the key is first used.")


class ApiKeyListResponse(BaseModel):
    """Active, non-expired keys visible to the caller.

    Scope is not a field: an admin sees the tenant's keys, a non-admin sees only
    its own department's. Revoked and expired keys are excluded rather than
    flagged.
    """

    keys: list[ApiKeyListItem]


# ── the public settings families ─────────────────────────────────────────────
#
# Each family answers a GET with the stored values or the environment defaults,
# and a PUT with the same body plus `updated_at`. That difference is modelled by
# subclassing rather than by one model with an optional `updated_at`: a GET never
# sets it, and the GET schema should not suggest it might appear.
#
# `source` is NOT a general settings field. Only `rate_limit` returns it; the
# other three families return values alone, and adding one would be a contract
# change rather than documentation.
#
# NO PROVIDER CREDENTIAL IS DECLARED ANYWHERE HERE. The LLM and proxy families
# accept an `api_key` on the REQUEST and return only `api_key_masked` -- the
# stored value is encrypted at rest and masked on the way out. That asymmetry is
# deliberate and the models preserve it: there is no field on any response model
# that could carry a plaintext or encrypted key.


class ThresholdsResponse(BaseModel):
    """Active decision thresholds. Stored per tenant, or the environment default
    when nothing has been stored."""

    block_threshold:    float = Field(description="At or above this risk score the decision is BLOCK.")
    sanitize_threshold: float = Field(description="At or above this, and below the block threshold, the decision is SANITIZE.")


class ThresholdsUpdatedResponse(ThresholdsResponse):
    updated_at: str = Field(description="When this update was applied, ISO-8601 UTC with a Z suffix.")


class DetectionLayersResponse(BaseModel):
    """Which detection layers run. Disabling the LLM layer also closes proxy
    execution, which requires it."""

    rule_enabled: bool = Field(description="Deterministic pattern matching. The cheapest layer, and the only one that needs neither a model nor a provider.")
    ml_enabled:   bool = Field(description="The local classifier. Runs in-process and calls no external provider.")
    llm_enabled:  bool = Field(description="Semantic analysis by the configured LLM provider. Disabling it also closes proxy execution on `POST /v1/ai/request`, which requires this layer.")


class DetectionLayersUpdatedResponse(DetectionLayersResponse):
    updated_at: str = Field(description="When this update was applied, ISO-8601 UTC with a Z suffix.")


class LLMSettingsResponse(BaseModel):
    """The LLM detector's provider configuration.

    `api_key_masked` is the ONLY credential-derived field, and it is a mask --
    never the key. It is null when no key is stored, and `****` when one is
    stored but cannot be decrypted with the current secret.
    """

    provider:       str = Field(description="Which provider the LLM detector calls.")
    model:          str = Field(description="Model the detector asks for, spelled as that provider names it.")
    base_url:       str = Field(description="Endpoint the detector calls. Points at the provider, or at a compatible gateway in front of it.")
    timeout:        int = Field(description="Seconds the detector waits before giving up on the provider. A detector timeout fails closed: the request is blocked, not allowed through unscanned.")
    llm_trigger:    float = Field(description="Risk score at which the LLM detector is invoked.")
    api_key_masked: str | None = Field(description="Masked provider key, or null when none is stored. Never the key itself.")


class LLMSettingsUpdatedResponse(LLMSettingsResponse):
    updated_at: str = Field(description="When this update was applied, ISO-8601 UTC with a Z suffix.")


class RateLimitResponse(BaseModel):
    """The enforced per-minute limit for live keys.

    The only settings family that reports its `source`. Trial keys are limited
    separately by deployment configuration and are not represented here.
    """

    per_minute: int = Field(description="Requests a live key may make per minute on this tenant.")
    source:     str = Field(description="`database` when stored for this tenant, `environment` when the default is in force.")


class RateLimitUpdatedResponse(RateLimitResponse):
    updated_at: str = Field(description="When this update was applied, ISO-8601 UTC with a Z suffix.")


class ProxyProviderConfigResponse(BaseModel):
    """The tenant's proxy provider configuration.

    Returned identically by the read and the upsert, so one model serves both.
    `api_key_masked` follows the same rule as the LLM family: a mask or null,
    never the stored key, which is encrypted at rest.
    """

    provider:        str = Field(description="`openai`, `ollama` or `custom`.")
    base_url:        str = Field(description="Endpoint the proxy forwards to.")
    api_key_masked:  str | None = Field(description="Masked provider key, or null when the provider needs none.")
    default_model:   str = Field(description="Used when a chat request omits `model`. A request may name its own as `provider/model`; with neither, the request is refused.")
    timeout_seconds: int = Field(description="Seconds the proxy waits for the provider before answering `504`.")
    created_at:      str | None = Field(description="ISO-8601 UTC with a Z suffix.")
    updated_at:      str | None = Field(description="ISO-8601 UTC with a Z suffix.")


# ── POST /v1/chat/completions, the OpenAI-compatible route ───────────────────
#
# This route speaks a FOREIGN protocol. Its bodies are shaped for OpenAI client
# libraries, so the models below describe THAT contract and deliberately share
# nothing with the WrapSec response models above -- in particular, its errors do
# not use `ErrorEnvelope`.
#
# WHAT THIS IMPLEMENTATION ACTUALLY RETURNS, measured rather than recalled from
# the OpenAI specification:
#
#   * no `created` field. Real OpenAI sends one; this route does not, and adding
#     it here would advertise a field no caller receives;
#   * `id` is `wrapsec-{trace_id}`, not the provider's completion id;
#   * exactly ONE choice, index 0. The proxy does not support `n`;
#   * `usage` appears only when the provider sent one. It is passed through
#     unchanged -- observability, never metering -- and is absent otherwise;
#   * `wrapsec` appears only when the caller opts in with
#     `X-WrapSec-Inline-Meta: true`. The same information is always on the
#     `X-WrapSec-*` response headers;
#   * no tool or function calls. `tools`, `tool_choice` and `functions` are
#     rejected at the request schema, and a `tool` role is refused before the
#     handler runs, so no tool-call response shape exists to model;
#   * no streaming. The request schema forbids unknown fields and has no
#     `stream`, so `stream: true` is a 422 and there is no StreamingResponse
#     anywhere on this path. Streaming is therefore NOT a model exception here --
#     it does not exist.


class ChatMessage(BaseModel):
    role:    str = Field(description="Always `assistant` on a response.")
    content: str = Field(description="The reply, after the output guard has run. Sanitized in place when it was rewritten.")


class ChatChoice(BaseModel):
    index:         int = Field(description="Always 0: this proxy returns a single choice.")
    message:       ChatMessage
    finish_reason: str | None = Field(description="Passed through from the provider, for example `stop`.")


class ChatCompletionMeta(BaseModel):
    """The opt-in `wrapsec` block. Present only with `X-WrapSec-Inline-Meta:
    true`; the same values are always available on the response headers."""

    trace_id:             str
    decision:             str = Field(description="Verdict on the input: ALLOW, SANITIZE or BLOCK.")
    input_primary_reason: str
    input_confidence:     float
    input_sanitized:      bool
    output_decision:      str | None
    output_sanitized:     bool
    execution_status:     str
    provider:             str | None
    model:                str | None
    total_latency_ms:     int = Field(description="End to end, including detection on both sides.")


class ChatCompletionResponse(BaseModel):
    """OpenAI-compatible chat completion.

    Compatible, not equivalent: see the module note above for what this
    implementation omits and adds.
    """

    id:      str = Field(description="`wrapsec-{trace_id}`, not the provider's completion id.")
    object:  str = Field(description="Always `chat.completion`.")
    model:   str = Field(description="The model the provider reported using.")
    choices: list[ChatChoice]

    usage: dict[str, Any] | None = Field(
        default     = None,
        description = "The provider's own token counts, passed through when it sent them; absent otherwise. Observability only.",
    )
    wrapsec: ChatCompletionMeta | None = Field(
        default     = None,
        description = "Present only when the caller sets `X-WrapSec-Inline-Meta: true`.",
    )


class OpenAIErrorDetail(BaseModel):
    message: str
    type:    str = Field(description="OpenAI error family, for example `invalid_request_error`.")
    code:    str = Field(description="Stable code, for example `input_blocked` or `invalid_model_format`.")


class OpenAIErrorResponse(BaseModel):
    """The OpenAI-compatible error envelope this route returns for its OWN
    refusals and upstream failures.

    Deliberately NOT `ErrorEnvelope`: the callers here are OpenAI client
    libraries, which parse `error.message` / `error.type` / `error.code`.

    `wrapsec` carries diagnostic context whose keys vary by path -- a refusal
    before any scanning has only the trace id, while a policy block adds the
    decision, reason, threats and confidence. Typed as a free-form object for
    that reason, rather than enumerating one path's keys and misdescribing the
    others.
    """

    error:   OpenAIErrorDetail
    wrapsec: dict[str, Any] = Field(description="Diagnostic context. Always carries `trace_id`; other keys depend on the path.")


# ── the audit item projection, shared by two routes ──────────────────────────
#
# `_format_item` in the audit endpoints builds this, and BOTH `GET /v1/audit/logs`
# and `GET /v1/agent-runs/{run_id}` serve it -- as `items` and as `turns`
# respectively. One model, so the two cannot drift; it was called `AgentRunTurn`
# when only the timeline was modelled, which stopped being accurate the moment the
# audit list route reused it.
#
# Every one of its keys is set on every row, so NOTHING here is optional: a field
# that can be empty is present and NULL, and none carries a default. That is the
# distinction the convention turns on -- a default of None would say the key can
# be missing, which for this projection is false and would let a writer drop a
# field without the model noticing.


class AuditItem(BaseModel):
    """One audited scan, as persisted.

    No per-layer detector scores appear in this projection at all -- neither
    `detection_scores` nor `guardrail_scores` nor `assessment` -- so unlike the
    scan response and the single-request read-back it carries no caller-dependent
    field. There is nothing here to restrict.
    """

    trace_id:        str = Field(description="Identifier of this scan.")
    timestamp:       str = Field(description="ISO-8601 UTC with a Z suffix.")
    tenant_id:       str | None
    decision:        str = Field(description="ALLOW, SANITIZE or BLOCK for the input scan.")
    output_decision: str | None = Field(description="Verdict on the model's reply. Null unless this turn went through the proxy.")
    provider:        str | None = Field(description="Null unless this turn went through the proxy.")
    model:           str | None = Field(description="Null unless this turn went through the proxy.")
    primary_reason:  str | None
    risk_score:      float
    confidence:      float | None
    confidence_band: str | None
    threats:         list[str]
    input_hash:      str = Field(description="Hash of the scanned input; the input itself is not stored here.")
    detection_mode:  str
    execution_mode:  str
    latency_ms:      float
    key_id:          str | None
    dept_id:         str | None
    dept_name:       str | None = Field(description="Resolved name; null when the department no longer exists.")
    app_id:          str | None
    app_name:        str | None = Field(description="Resolved name; null when the application no longer exists.")
    user_id:         str | None
    source:          str | None
    ip_address:      str | None
    attribution_verified: bool
    policy_source:   str | None = Field(description="Which policy layer resolved the decision, or `cache` for a cache hit.")
    input_length:    int
    severity:        str = Field(description="INFO, WARNING, ERROR or CRITICAL.")
    session_id:      str | None = Field(description="Caller-supplied correlation; never an authorization input.")
    turn_index:      int | None = Field(description="Zero-based position within the session, as the caller supplied it.")
    run_id:          str | None
    input_source:    str = Field(description="Declared provenance, for example `user_prompt` or `retrieved_document`.")
    record_hash:     str | None = Field(description="Hash-chain value for this row.")
    prev_hash:       str | None = Field(description="Preceding row's hash. Null for the first row in a tenant's chain.")


class AgentRunResponse(BaseModel):
    """A run's scans as an ordered timeline (turn_index, then time).

    An unknown or out-of-scope run_id is not an error: it returns this same
    envelope with `count: 0` and an empty `turns`, which is what keeps one
    tenant's run ids from being probed against another's.
    """

    run_id: str = Field(description="Echoed back exactly as requested.")
    count:  int = Field(description="Number of turns returned, bounded by `limit`.")
    turns:  list[AuditItem]


# ── GET /v1/audit/logs ───────────────────────────────────────────────────────


class AuditLogsResponse(BaseModel):
    """A page of audited scans.

    `total` counts everything matching the filters, not the page, so a caller
    paginates on it. The page itself is bounded by `limit`/`offset`, which are
    query parameters and are not echoed in the body. No match is `total: 0` with
    an empty `items` -- never a 404.
    """

    total: int = Field(description="Matching rows across all pages, for pagination.")
    items: list[AuditItem] = Field(description="This page, in the requested sort order.")


# ── GET /v1/audit/stats ──────────────────────────────────────────────────────


class TopThreat(BaseModel):
    category: str = Field(description="Threat category, for example PROMPT_INJECTION.")
    count:    int = Field(description="Occurrences within the filtered range.")


class SeverityCounts(BaseModel):
    """Always all four keys, zero-filled. A severity absent from the range is a
    zero rather than a missing key, so a dashboard needs no defaulting."""

    CRITICAL: int
    HIGH:     int
    MEDIUM:   int
    LOW:      int


class AuditStatsResponse(BaseModel):
    """Aggregates over the filtered range.

    An empty range returns this same shape with every count and rate zeroed --
    the handler has a separate zero branch precisely so the contract does not
    change when there is nothing to aggregate.

    Counts sit alongside rates deliberately: reconstructing a count from
    `rate * total` drifts by one against `GET /v1/audit/logs?decision=BLOCK`,
    because the rate is rounded to four decimals.
    """

    period_from:     str = Field(description="Start of the range, echoed from the query or defaulted to now.")
    period_to:       str = Field(description="End of the range, echoed from the query or defaulted to now.")
    total_requests:  int
    block_count:     int
    sanitize_count:  int
    allow_count:     int
    block_rate:      float = Field(description="Fraction of matching requests blocked, rounded to 4 decimals.")
    sanitize_rate:   float
    allow_rate:      float
    avg_latency_ms:  float
    p95_latency_ms:  float = Field(description="95th percentile, interpolated on PostgreSQL.")
    avg_risk:        float
    top_threats:     list[TopThreat] = Field(description="Most frequent categories first; empty when nothing matched.")
    severity_counts: SeverityCounts


# ── GET /v1/ai/requests/{trace_id} ───────────────────────────────────────────


class RecordAttribution(BaseModel):
    tenant_id:            str | None
    dept_id:              str | None
    dept_name:            str | None = Field(description="Resolved department name; null when the lookup found nothing.")
    app_id:               str | None
    app_name:             str | None = Field(description="Resolved application name; null when the lookup found nothing.")
    source:               str | None
    user_id:              str | None
    key_id:               str | None
    ip_address:           str | None
    user_agent:           str | None
    attribution_verified: bool


class RecordProcessing(BaseModel):
    latency_ms:     float | None
    llm_invoked:    bool | None
    detection_mode: str | None
    execution_mode: str | None
    policy_source:  str | None = Field(description="Which policy layer resolved the decision, or `cache` for a cache hit.")


class RecordProxyDetail(BaseModel):
    """Proxy lifecycle, joined from `proxy_interactions`. Present only for a
    request executed in proxy mode."""

    provider:              str | None
    model:                 str | None
    provider_latency_ms:   int | None
    total_latency_ms:      int | None
    execution_status:      str | None
    input_primary_reason:  str | None
    input_confidence:      float | None
    input_threats:         list[str]
    input_attack_type:     str | None
    input_raw:             str | None
    input_sanitized:       str | None
    output_decision:       str | None
    output_primary_reason: str | None
    output_confidence:     float | None
    output_threats:        list[str]
    output_raw:            str | None
    output_sanitized:      str | None
    behavior_flag:         str | None
    output_flags:          Any | None


class RequestRecordResponse(BaseModel):
    trace_id:       str
    timestamp:      str = Field(description="ISO-8601 UTC with a Z suffix.")
    execution_mode: str | None
    is_proxy:       bool
    severity:       str | None = Field(description="INFO, WARNING, ERROR or CRITICAL.")
    attribution:    RecordAttribution

    decision:        str
    risk_score:      float | None
    primary_reason:  str | None
    confidence:      float | None
    confidence_band: str | None
    threats:         list[str]

    input_hash:   str = Field(description="Hash of the scanned input; the input itself is never stored here.")
    input_length: int

    run_id:       str | None = Field(description="Caller-supplied agent-run correlation; never an authorization input.")
    session_id:   str | None
    turn_index:   int | None
    input_source: str | None = Field(description="Declared provenance, for example `user_prompt` or `retrieved_document`.")

    detection_scores: dict[str, float] = Field(
        description="Per-detector scores as persisted. EMPTY for a caller that may not read layer scores -- "
                    "the key stays present so consumers need no special case.",
    )
    guardrail_scores: dict[str, float] = Field(
        description="Guardrail scores as persisted. Empty under the same restriction as detection_scores.",
    )

    processing: RecordProcessing
    proxy:      RecordProxyDetail | None = Field(
        default     = None,
        description = "Proxy lifecycle detail. Absent for a scan-only request.",
    )
