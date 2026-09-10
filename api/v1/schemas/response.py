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

# -- published allowed values -------------------------------------------------
#
# METADATA ONLY. These reach the OpenAPI schema and change nothing at runtime:
# the fields stay `str`, and nothing validates against them. A value outside a
# list is still served.
#
# WHY NOT AN ENUM TYPE. Several of these fields are read back from `VARCHAR`
# columns written by earlier builds, and response validation is fail-closed, so
# an enum would turn a historical row into a 500 rather than a read. Publishing
# the vocabulary documents it for a code generator without taking that risk.
# The distinction is recorded as F-030; typing them remains blocked on evidence
# this repository cannot supply.
#
# This module imports nothing, by design, so each list below MIRRORS a source of
# truth in another layer rather than deriving from it. That mirroring is not
# left to trust: `tests/unit/test_openapi_contract.py` asserts every list equals
# its source, and fails if either side moves.

DECISIONS         = ["BLOCK", "SANITIZE", "ALLOW"]              # domain.enums.DecisionType
SEVERITIES        = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]       # domain.enums.RiskLevel
# The same four bands under the name the field uses. An alias, not a second list:
# `severity` and `risk_level` are both `RiskLevel`, and giving them one list means
# they cannot drift apart.
RISK_LEVELS       = SEVERITIES                                  # domain.enums.RiskLevel

# The error envelope's own two vocabularies. Both come from the catalog, which is
# the only producer: `error_response` is typed to `ErrorCode` and reads severity
# off the catalog entry, so nothing else can reach `ErrorDetail`.
#
# SEVERITIES is a DIFFERENT list that happens to share a name-shape: that one is
# threat banding (`RiskLevel`), this one is how bad the FAILURE is. They are not
# interchangeable and must not be merged.
ERROR_CODES       = ["ACCOUNT_DISABLED", "ACCOUNT_LOCKED",
                     "CANNOT_DEACTIVATE_SELF", "CONFLICT", "DETECTION_ERROR",
                     "FEATURE_UNAVAILABLE", "FORBIDDEN", "IDEMPOTENCY_CONFLICT",
                     "INTERNAL_ERROR", "INVALID_CREDENTIALS", "INVALID_PASSWORD",
                     "INVALID_REQUEST", "INVALID_TOKEN", "IP_NOT_ALLOWED",
                     "LAST_ADMIN", "LLM_UNAVAILABLE", "MODEL_REQUIRED",
                     "NOT_FOUND", "PASSWORD_CHANGE_REQUIRED",
                     "PROXY_REQUIRES_API_KEY", "RATE_LIMIT_EXCEEDED",
                     "SESSION_INVALIDATED", "STREAM_NOT_SUPPORTED",
                     "TENANT_SUSPENDED", "UNAUTHORIZED", "VALIDATION_ERROR"]

# The two the catalog actually uses. `ErrorSeverity` also defines INFO, but no
# entry carries it, so publishing it would promise a value no response can hold.
ERROR_SEVERITIES  = ["ERROR", "WARNING"]                     # errors.catalog, values in use
DETECTION_MODES   = ["fast", "full"]                            # domain.enums.DetectionMode
EXECUTION_MODES   = ["scan_only", "proxy"]                      # domain.enums.ExecutionMode
INPUT_SOURCES     = ["user_prompt", "tool_output",              # domain.enums.InputSource
                     "retrieved_document", "external_content"]
CONFIDENCE_BANDS  = ["HIGH", "MEDIUM", "LOW"]                   # engine.scoring.confidence
PRIMARY_REASONS   = ["SYSTEM_ERROR", "PII_GUARDRAIL_BLOCK",     # engine.scoring.primary_reason
                     "PII_GUARDRAIL_SANITIZE", "TOXICITY_GUARDRAIL_BLOCK",
                     "RULE_DETECTOR", "ML_DETECTOR", "LLM_DETECTOR",
                     "NO_THREAT_DETECTED"]
EXECUTION_STATUSES = ["SUCCESS", "BLOCKED", "OUTPUT_BLOCKED",   # api.v1.endpoints.proxy STATUS_*
                      "FAILED", "TIMEOUT"]
PROXY_PROVIDERS   = ["custom", "ollama", "openai"]              # engine.proxy.router SUPPORTED_PROVIDERS
KEY_TYPES         = ["live", "trial"]                           # api.v1.endpoints.keys KeyType
CONFIG_SOURCES    = ["database", "environment"]                 # health.py + settings.py rate_limit
EDITIONS          = ["oss", "enterprise"]                       # capabilities.py

# The probes report on two different scales, and they are not merged. Infra is
# reachable or it is not; a detector tier additionally distinguishes "loaded" from
# "running without its model". Publishing one union would tell a reader that a
# database can be `healthy`, which it cannot be.
HEALTH_STATUS           = ["ok"]                                # health.py, the liveness+build probe
LIVENESS_STATUS         = ["alive"]                             # health.py, the process probe
READINESS_STATUS        = ["ready", "degraded"]                 # health.py, aggregate over checks
INFRA_CHECK_STATUSES    = ["ok", "unavailable"]                 # health.py, database and redis
DETECTOR_CHECK_STATUSES = ["healthy", "degraded", "unavailable"]  # health.py, the detector tiers
POLICY_SOURCES    = ["system_default", "department_override",   # services.policy_resolver
                     "application_override", "cache"]           #   + the cache path in ai.py
THREAT_CATEGORIES = ["PROMPT_INJECTION", "JAILBREAK",           # domain.enums.ThreatCategory
                     "MALICIOUS_INTENT", "DATA_EXFILTRATION",
                     "PII", "TOXICITY", "BENIGN"]

# The chat success body is NARROWER than the vocabularies above, and the lists
# below say so rather than over-publishing. `ChatCompletionMeta` describes the
# meta on a 200, and three states cannot reach it -- the route returns first:
#
#     proxy.py:1125   if input_decision  == "BLOCK":  ...  return
#     proxy.py:1427   if output_decision == "BLOCK":  ...  return
#     proxy.py:1475   execution_status = STATUS_SUCCESS   (unconditional)
#
# Publishing BLOCK or TIMEOUT here would advertise a state a 200 body cannot
# carry, and send an integrator to write a branch that never runs. Each list is
# asserted to be a SUBSET of its parent, and the three lines above are pinned,
# so removing an early return fails a test instead of silently making this wrong.
#
# `input_primary_reason` is deliberately NOT narrowed the same way. Which reasons
# accompany a non-BLOCK decision is a property of the scorer, not a structural
# guarantee of this route, so it publishes the full vocabulary.
CHAT_META_DECISIONS = ["SANITIZE", "ALLOW"]                     # DECISIONS minus BLOCK
CHAT_META_STATUSES  = ["SUCCESS"]                               # EXECUTION_STATUSES on a 200
CHAT_OBJECT         = ["chat.completion"]                       # proxy.py, the success body
CHAT_RESPONSE_ROLES = ["assistant"]                             # proxy.py, the success body


def _allowed(values: list[str]):
    """Attach `enum` to the STRING schema, wrapped in `anyOf` or not.

    A plain `json_schema_extra={"enum": [...]}` lands the keyword beside `anyOf`
    on a nullable field, and JSON Schema ANDs siblings -- so `null` satisfies the
    `anyOf` and then fails the `enum`, and the published contract says a nullable
    field cannot be null. The runtime happily returns null, so the schema would be
    describing something the API does not do.

    Passing a callable instead lets the enum be placed on the branch it belongs
    to. Purely a schema concern: nothing here validates, and the field stays a
    permissive `str`.
    """
    def _apply(schema: dict) -> None:
        for branch in schema.get("anyOf") or []:
            if branch.get("type") == "string":
                branch["enum"] = values
                return
        schema["enum"] = values

    return _apply

# The detector's own `provider` and the chat `finish_reason` are deliberately
# absent. The first is published straight from an unvalidated environment
# variable; the second is whatever the upstream provider returned. Neither has a
# vocabulary this API controls, so neither gets one here.
#
# `AuditItem.source` is absent for the same reason: it echoes
# `metadata.source` from the caller's own request body, so its values are
# whatever integrators send.
#
# `AuditItem.threats` holds ThreatCategory values but is a `list[str]`, and the
# enum belongs on the ITEMS rather than the array. `json_schema_extra` on the
# field would attach it to the array itself and publish something false. Left
# for a pass that handles arrays deliberately.


# ── the canonical error envelope ─────────────────────────────────────────────
# One shape for every WrapSec error, built by `errors/response.py`. Declared here
# so routes can reference it in `responses={...}`; it is not per-endpoint, and a
# family must never define its own. The OpenAI-compatible envelope on
# `/v1/chat/completions` is a separate protocol shape and is not modelled here.


class ErrorDetail(BaseModel):
    code:     str = Field(description="Stable machine-readable error code from the catalog.", json_schema_extra=_allowed(ERROR_CODES))
    severity: str = Field(description="How bad the failure is: ERROR or WARNING. Not threat severity.", json_schema_extra=_allowed(ERROR_SEVERITIES))
    key:      str = Field(examples=["errors.NOT_FOUND"], description="Localization key; clients may resolve their own text from it.")
    params:   dict[str, Any] = Field(examples=[{"resource": "request"}], description="Values interpolated into the localized message.")
    message:  str = Field(description="English message. Localized clients should prefer key + params.")
    trace_id: str = Field(examples=["req_2c31dee1bfda40a0b178c932d659f039"], description="Correlates the failure with the audit trail.")
    invalid_params: list[dict[str, Any]] | None = Field(examples=[[{"field": "trace_id", "code": "INVALID_VALUE", "key": "forms.errors.INVALID_VALUE", "params": {}}]], 
        default     = None,
        description = "Per-field detail, present only on validation failures.",
    )


class ErrorEnvelope(BaseModel):
    error: ErrorDetail = Field(description="The failure. Every error this API returns is a single object under this key.")


# ── the security assessment, shared by the scan and batch responses ──────────


class AssessmentLayer(BaseModel):
    """One detector's contribution.

    `score` is omitted -- not nulled -- for a caller that does not hold
    `settings:read`, or for any trial key. `name` and `decision` are always
    present, so a restricted caller still sees which layer landed in which
    bucket.
    """

    name:     str = Field(examples=["rule_score"], description="Detector name, for example `rule_score` or `ml_score`.")
    decision: str = Field(description="This layer's classification: ALLOW, SANITIZE or BLOCK.", json_schema_extra=_allowed(DECISIONS))
    score:    float | None = Field(examples=[0.86], 
        default     = None,
        description = "0.0-1.0 contribution. Absent when the caller may not read layer scores.",
    )


class Assessment(BaseModel):
    """The self-contained verdict. Agents and the protocol adapter consume this
    object; the flat top-level fields duplicate part of it for compatibility."""

    decision:        str = Field(description="ALLOW, SANITIZE or BLOCK.", json_schema_extra=_allowed(DECISIONS))
    risk_score:      float = Field(examples=[0.86], description="Aggregate risk, 0.0-1.0.")
    risk_level:      str = Field(description="Banded risk: LOW, MEDIUM, HIGH or CRITICAL.", json_schema_extra=_allowed(RISK_LEVELS))
    primary_reason:  str | None = Field(description="Dominant reason for the decision, null if none applied.", json_schema_extra=_allowed(PRIMARY_REASONS))
    confidence:      float | None = Field(examples=[0.91], description="Confidence in the decision, 0.0-1.0.")
    confidence_band: str | None = Field(description="LOW, MEDIUM or HIGH.", json_schema_extra=_allowed(CONFIDENCE_BANDS))
    threats:         list[str] = Field(examples=[["PROMPT_INJECTION"]], description="Threat categories detected.")
    layers:          list[AssessmentLayer] = Field(description="Per-detector contributions.")
    posture:         dict[str, Any] | None = Field(examples=[{"dimension": "source", "input_source": "retrieved_document", "tier": "untrusted", "applied_delta": 0.1, "effective_block": 0.6, "effective_sanitize": 0.3}], 
        default     = None,
        description = "Source-aware threshold shift. Absent unless provenance changed the posture.",
    )


# ── POST /v1/ai/request ──────────────────────────────────────────────────────


class ScanProcessing(BaseModel):
    latency_ms:     float = Field(examples=[41.2], description="Detection time in milliseconds.")
    llm_invoked:    bool = Field(description="Whether the LLM detector ran.")
    detection_mode: str = Field(description="`fast` runs the cheap layers; `full` adds the LLM detector.", json_schema_extra=_allowed(DETECTION_MODES))
    execution_mode: str = Field(description="scan_only or proxy.", json_schema_extra=_allowed(EXECUTION_MODES))


class ScanDebug(BaseModel):
    """Admin-only diagnostics. Present only when an admin key sets
    `options.debug`, and never cached."""

    rule_score:      float = Field(examples=[0.86], description="Raw score from the pattern layer, 0.0-1.0.")
    ml_score:        float = Field(examples=[0.74], description="Raw score from the classifier, 0.0-1.0.")
    llm_score:       float = Field(examples=[0.31], description="Raw score from the LLM detector, 0.0-1.0.")
    pii_score:       float = Field(examples=[0.0], description="Raw score from the PII guardrail, 0.0-1.0.")
    layer_decisions: dict[str, str] = Field(examples=[{"rule": "BLOCK", "ml": "SANITIZE", "llm": "ALLOW"}], description="What each detection layer would have decided on its own score, keyed by layer. The guardrail is not included.")


class ScanResponse(BaseModel):
    trace_id:             str = Field(examples=["req_2c31dee1bfda40a0b178c932d659f039"], description="Identifier for this scan; reads back via GET /v1/ai/requests/{trace_id}.")
    decision:             str = Field(description="ALLOW, SANITIZE or BLOCK.", json_schema_extra=_allowed(DECISIONS))
    decision_version:     str = Field(examples=["v1.0"], description="Version of the decision contract.")
    risk_score:           float = Field(examples=[0.86], description="Aggregate risk, 0.0-1.0.")
    primary_reason:       str | None = Field(description="Dominant reason, null if none applied.", json_schema_extra=_allowed(PRIMARY_REASONS))
    confidence:           float | None = Field(examples=[0.91], description="Confidence in the decision, 0.0-1.0.")
    confidence_band:      str | None = Field(description="LOW, MEDIUM or HIGH.", json_schema_extra=_allowed(CONFIDENCE_BANDS))
    threats:              list[str] = Field(examples=[["PROMPT_INJECTION"]], description="Threat categories detected.")
    sanitization_applied: bool = Field(description="True only when the input text was actually rewritten.")
    processing:           ScanProcessing = Field(description="Timing and the modes this scan ran under.")
    assessment:           Assessment = Field(description="The same decision in detail: per-layer contributions and the summary. Not a second opinion.")

    sanitized_input: str | None = Field(examples=["Contact me at [EMAIL REDACTED] about the invoice."], 
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

    # `examples`, not `example`: this document is OpenAPI 3.1, whose Schema Object
    # IS JSON Schema 2020-12, and the singular form is deprecated there.
    model_config = {
        "json_schema_extra": {
            "examples": [{
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
                    "risk_level":      "LOW",
                    "primary_reason":  "NO_THREAT_DETECTED",
                    "confidence":      1.0,
                    "confidence_band": "HIGH",
                    "threats":         [],
                    "layers": [
                        {"name": "rule_score", "score": 0.0, "decision": "ALLOW"},
                        {"name": "ml_score",   "score": 0.0, "decision": "ALLOW"},
                    ],
                },
            }]
        }
    }


# ── POST /v1/ai/scan-batch ───────────────────────────────────────────────────


class BatchSummary(BaseModel):
    blocked:           int = Field(description="Items decided BLOCK.")
    sanitized:         int = Field(description="Items decided SANITIZE.")
    allowed:           int = Field(description="Items decided ALLOW.")
    highest_risk:      float = Field(examples=[0.86], description="Highest risk score across the batch.")
    highest_risk_item: str | None = Field(examples=["chunk-7"], 
        description="Caller-supplied id of the riskiest item. Null when no item scored above zero, "
                    "and null when the riskiest item carried no id.",
    )
    threats:           list[str] = Field(examples=[["PROMPT_INJECTION"]], description="Union of threat categories across the batch, sorted.")


class BatchItemResult(BaseModel):
    id:         str | None = Field(examples=["chunk-7"], description="The caller's own reference for this item, echoed back. Null if none was sent.")
    trace_id:   str = Field(examples=["req_2c31dee1bfda40a0b178c932d659f039"], description="Identifier for this item's scan; each item is audited independently.")
    decision:   str = Field(description="ALLOW, SANITIZE or BLOCK.", json_schema_extra=_allowed(DECISIONS))
    assessment: Assessment = Field(description="The same decision in detail, as on a single scan.")


class ScanBatchResponse(BaseModel):
    count:   int = Field(description="Number of items scanned.")
    summary: BatchSummary = Field(description="Aggregate counts across the batch.")
    results: list[BatchItemResult] = Field(description="One result per item, in request order.")


# ── health and capabilities ──────────────────────────────────────────────────


class HealthResponse(BaseModel):
    """Unauthenticated liveness plus build identity."""

    status:  str = Field(description="Always `ok` -- reaching this endpoint at all is the signal.", json_schema_extra=_allowed(HEALTH_STATUS))
    version: str = Field(examples=["1.0.0"], description="Running build. Deliberately unauthenticated: it is how a deployment is verified.")


class LivenessResponse(BaseModel):
    status: str = Field(description="Always `alive`. The process answered; nothing else is checked.", json_schema_extra=_allowed(LIVENESS_STATUS))


class HealthChecks(BaseModel):
    """Per-component status. `ok` / `unavailable` for infrastructure,
    `healthy` / `degraded` / `unavailable` for the detector tiers."""

    database:             str = Field(description="`ok` when a trivial query succeeded. Required: `unavailable` here answers 503.", json_schema_extra=_allowed(INFRA_CHECK_STATUSES))
    redis:                str = Field(description="`ok` when the cache answered a ping. Required: `unavailable` here answers 503.", json_schema_extra=_allowed(INFRA_CHECK_STATUSES))
    tfidf_detector:       str = Field(description="Tier 1, REQUIRED. Degraded here means the instance refuses traffic fail-closed.", json_schema_extra=_allowed(DETECTOR_CHECK_STATUSES))
    transformer_detector: str = Field(description="Tier 2, OPTIONAL. Degraded on a default build and does not affect the status code.", json_schema_extra=_allowed(DETECTOR_CHECK_STATUSES))


class ReadinessResponse(BaseModel):
    """Readiness. The STATUS CODE is the contract and the body is the detail --
    an orchestrator routes on the code.

    The same body shape is returned with 200 and with 503, so one model
    describes both. `status: degraded` with 200 means serving with less signal
    (Tier 2 absent); 503 means a required component is down.
    """

    status: str = Field(description="`ready` when every check passed, `degraded` when any did not.", json_schema_extra=_allowed(READINESS_STATUS))
    checks: HealthChecks = Field(description="Per-component detail behind the status. Informational: an orchestrator routes on the status code.")


class ConfigThresholds(BaseModel):
    """`source` always; the values only for a caller holding `settings:read`.

    The restricted form is the same object with the numbers ABSENT, not nulled:
    a null would still confirm a threshold exists and is being withheld, and the
    point of the restriction is that a caller cannot calibrate against it.
    """

    source:   str = Field(description="`database` when stored for this tenant, `environment` otherwise.", json_schema_extra=_allowed(CONFIG_SOURCES))
    block:    float | None = Field(examples=[0.7], default=None, description="Absent without `settings:read`.")
    sanitize: float | None = Field(examples=[0.4], default=None, description="Absent without `settings:read`.")


class ConfigDetectionLayers(BaseModel):
    source: str = Field(description="`database` when stored for this tenant, `environment` otherwise.", json_schema_extra=_allowed(CONFIG_SOURCES))
    rule:   bool | None = Field(default=None, description="Absent without `settings:read`.")
    ml:     bool | None = Field(default=None, description="Absent without `settings:read`.")
    llm:    bool | None = Field(default=None, description="Absent without `settings:read`.")


class ConfigLLM(BaseModel):
    source:      str = Field(description="`database` when stored for this tenant, `environment` otherwise.", json_schema_extra=_allowed(CONFIG_SOURCES))
    provider:    str | None = Field(default=None, description="Absent without `settings:read`.")
    model:       str | None = Field(examples=["llama3.2"], default=None, description="Absent without `settings:read`.")
    llm_trigger: float | None = Field(examples=[0.2], default=None, description="Absent without `settings:read`.")
    timeout:     int | None = Field(examples=[30], default=None, description="Absent without `settings:read`.")


class ConfigRateLimit(BaseModel):
    source:     str = Field(description="`database` when stored for this tenant, `environment` otherwise.", json_schema_extra=_allowed(CONFIG_SOURCES))
    per_minute: int | None = Field(examples=[60], default=None, description="Absent without `settings:read`.")


class HealthConfigResponse(BaseModel):
    """The configuration in force, for deployment verification.

    Every caller gets the same TOP-LEVEL keys; the difference is inside each
    section. A caller without `settings:read` -- VIEWER, or any trial key -- sees
    each section reduced to its `source` marker, which says whether configuration
    was customised without saying what it was set to. No provider credential is
    ever included, for any caller.
    """

    version:          str = Field(examples=["1.0.0"], description="Running build. Unrestricted here, because the unauthenticated `GET /health` already returns it.")
    thresholds:       ConfigThresholds = Field(description="Decision thresholds. `source` reaches every caller; the values need `settings:read`.")
    detection_layers: ConfigDetectionLayers = Field(description="Which detection layers run. `source` reaches every caller; the values need `settings:read`.")
    llm:              ConfigLLM = Field(description="LLM detector configuration. `source` reaches every caller; the values need `settings:read`.")
    rate_limit:       ConfigRateLimit = Field(description="The enforced per-minute limit. `source` reaches every caller; the value needs `settings:read`.")


class CapabilitiesResponse(BaseModel):
    """Which optional plugin capabilities are effective in this DEPLOYMENT.

    Process-global, not per tenant, and informational only -- never an
    authorization control. The OSS build returns an empty list and `oss`.
    """

    edition:      str = Field(description="`oss` with no capabilities registered, `enterprise` otherwise. Display metadata, not a claim.", json_schema_extra=_allowed(EDITIONS))
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

    id:                   str = Field(examples=["0f9c1d3e-5a72-4b18-9e6d-2c84f1057ab3"], description="Row identifier.")
    trace_id:             str = Field(examples=["req_2c31dee1bfda40a0b178c932d659f039"], description="Correlates with the audit trail.")
    created_at:           str | None = Field(examples=["2026-08-26T14:22:31.482Z"], description="ISO-8601 UTC with a Z suffix.")
    key_id:               str | None = Field(examples=["key_3f9a1c7d2e40"], description="Owning API key, with the internal `key:` prefix stripped. Null for a system record.")
    user_id:              str | None = Field(description="The proxy path records no end-user identifier, so this is always null.")
    input_decision:       str = Field(description="Verdict on the prompt: ALLOW, SANITIZE or BLOCK.", json_schema_extra=_allowed(DECISIONS))
    input_primary_reason: str = Field(description="Dominant reason behind the verdict on the prompt.", json_schema_extra=_allowed(PRIMARY_REASONS))
    input_confidence:     float = Field(examples=[0.91], description="Confidence in the verdict on the prompt, 0.0-1.0.")
    input_threats:        list[str] = Field(description="Threat categories detected in the prompt.")
    input_attack_type:    str | None = Field(description="The first threat category detected in the prompt, or null when none was.", json_schema_extra=_allowed(THREAT_CATEGORIES))
    provider:             str | None = Field(description="Null when the request never reached a provider.", json_schema_extra=_allowed(PROXY_PROVIDERS))
    model:                str | None = Field(examples=["gpt-4o"], description="Model the provider reported using.")
    provider_latency_ms:  int | None = Field(examples=[412], description="Provider time only. Null when no call was made.")
    execution_status:     str = Field(description="How the proxied call ended.", json_schema_extra=_allowed(EXECUTION_STATUSES))
    output_decision:      str | None = Field(description="Verdict on the reply. Null when there was no reply to guard.", json_schema_extra=_allowed(DECISIONS))
    output_primary_reason: str | None = Field(description="Dominant reason behind the verdict on the reply.", json_schema_extra=_allowed(PRIMARY_REASONS))
    output_confidence:    float | None = Field(examples=[0.12], description="Confidence in the verdict on the reply, 0.0-1.0.")
    output_threats:       list[str] = Field(description="Threat categories detected in the reply.")
    behavior_flag:        str | None = Field(description="No writer sets this, so it is always null.")
    output_flags:         Any | None = Field(description="No writer sets this, so it is always null.")
    total_latency_ms:     int = Field(examples=[468], description="End to end, including detection.")


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

    key_id:     str = Field(examples=["key_3f9a1c7d2e40"], description="Stable identifier for this key. Safe to log and to display.")
    name:       str = Field(description="Label supplied at creation.")
    api_key:    str = Field(description="The raw key. Returned ONLY here, only at creation, and never again.")
    key_type:   str = Field(description="`live` or `trial`.", json_schema_extra=_allowed(KEY_TYPES))
    app_id:     str | None = Field(examples=["6bc1bee2-2e40-4b0f-9f1a-1e031fa8088a"], description="Set when the key is application-scoped.")
    dept_id:    str | None = Field(examples=["2b7e1516-28ae-4d2a-a6ab-f7158809cf4f"], description="Owning department. Creation requires one, directly or derived from the application.")
    tenant_id:  str | None = Field(examples=["8f14e45f-ceea-467a-9f2b-3c1a7d05e9b4"], description="Owning tenant.")
    created_at: str = Field(examples=["2026-08-26T09:05:12.004Z"], description="ISO-8601 UTC with a Z suffix.")
    expires_at: str | None = Field(examples=["2027-08-26T00:00:00.000Z"], description="Null when the key does not expire.")


class ApiKeyListItem(BaseModel):
    """A key as listed. Metadata only -- no credential, no hash.

    Carries three fields creation does not: the resolved department and
    application names, and `last_used_at`.
    """

    key_id:       str = Field(examples=["key_3f9a1c7d2e40"], description="Stable identifier for this key. Safe to log and to display.")
    name:         str = Field(description="Label supplied at creation.")
    app_id:       str | None = Field(examples=["6bc1bee2-2e40-4b0f-9f1a-1e031fa8088a"], description="Set when the key is application-scoped.")
    dept_id:      str | None = Field(examples=["2b7e1516-28ae-4d2a-a6ab-f7158809cf4f"], description="Owning department.")
    dept_name:    str | None = Field(description="Resolved name; null when the department no longer exists.")
    app_name:     str | None = Field(description="Resolved name; null when the application no longer exists.")
    key_type:     str = Field(description="`live` or `trial`; defaults to `live` for a row that predates the column.", json_schema_extra=_allowed(KEY_TYPES))
    created_at:   str = Field(examples=["2026-08-26T09:05:12.004Z"], description="ISO-8601 UTC with a Z suffix.")
    expires_at:   str | None = Field(examples=["2027-08-26T00:00:00.000Z"], description="Null when the key does not expire.")
    last_used_at: str | None = Field(examples=["2026-08-26T14:22:31.482Z"], description="Null until the key is first used.")


class ApiKeyListResponse(BaseModel):
    """Active, non-expired keys visible to the caller.

    Scope is not a field: an admin sees the tenant's keys, a non-admin sees only
    its own department's. Revoked and expired keys are excluded rather than
    flagged.
    """

    keys: list[ApiKeyListItem] = Field(description="Keys within the caller's scope.")


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

    block_threshold:    float = Field(examples=[0.7], description="At or above this risk score the decision is BLOCK.")
    sanitize_threshold: float = Field(examples=[0.4], description="At or above this, and below the block threshold, the decision is SANITIZE.")


class ThresholdsUpdatedResponse(ThresholdsResponse):
    updated_at: str = Field(examples=["2026-08-26T14:22:31.482Z"], description="When this update was applied, ISO-8601 UTC with a Z suffix.")


class DetectionLayersResponse(BaseModel):
    """Which detection layers run. Disabling the LLM layer also closes proxy
    execution, which requires it."""

    rule_enabled: bool = Field(description="Deterministic pattern matching. The cheapest layer, and the only one that needs neither a model nor a provider.")
    ml_enabled:   bool = Field(description="The local classifier. Runs in-process and calls no external provider.")
    llm_enabled:  bool = Field(description="Semantic analysis by the configured LLM provider. Disabling it also closes proxy execution on `POST /v1/ai/request`, which requires this layer.")


class DetectionLayersUpdatedResponse(DetectionLayersResponse):
    updated_at: str = Field(examples=["2026-08-26T14:22:31.482Z"], description="When this update was applied, ISO-8601 UTC with a Z suffix.")


class LLMSettingsResponse(BaseModel):
    """The LLM detector's provider configuration.

    `api_key_masked` is the ONLY credential-derived field, and it is a mask --
    never the key. It is null when no key is stored, and `****` when one is
    stored but cannot be decrypted with the current secret.
    """

    provider:       str = Field(description="Which provider the LLM detector calls.")
    model:          str = Field(examples=["llama3.2"], description="Model the detector asks for, spelled as that provider names it.")
    base_url:       str = Field(examples=["http://localhost:11434"], description="Endpoint the detector calls. Points at the provider, or at a compatible gateway in front of it.")
    timeout:        int = Field(examples=[30], description="Seconds the detector waits before giving up on the provider. A detector timeout fails closed: the request is blocked, not allowed through unscanned.")
    llm_trigger:    float = Field(examples=[0.2], description="Risk score at which the LLM detector is invoked.")
    api_key_masked: str | None = Field(examples=["sk-a...mnop"], description="Masked provider key, or null when none is stored. Never the key itself.")


class LLMSettingsUpdatedResponse(LLMSettingsResponse):
    updated_at: str = Field(examples=["2026-08-26T14:22:31.482Z"], description="When this update was applied, ISO-8601 UTC with a Z suffix.")


class RateLimitResponse(BaseModel):
    """The enforced per-minute limit for live keys.

    The only settings family that reports its `source`. Trial keys are limited
    separately by deployment configuration and are not represented here.
    """

    per_minute: int = Field(examples=[60], description="Requests a live key may make per minute on this tenant.")
    source:     str = Field(description="`database` when stored for this tenant, `environment` when the default is in force.", json_schema_extra=_allowed(CONFIG_SOURCES))


class RateLimitUpdatedResponse(RateLimitResponse):
    updated_at: str = Field(examples=["2026-08-26T14:22:31.482Z"], description="When this update was applied, ISO-8601 UTC with a Z suffix.")


class ProxyProviderConfigResponse(BaseModel):
    """The tenant's proxy provider configuration.

    Returned identically by the read and the upsert, so one model serves both.
    `api_key_masked` follows the same rule as the LLM family: a mask or null,
    never the stored key, which is encrypted at rest.
    """

    provider:        str = Field(description="`openai`, `ollama` or `custom`.", json_schema_extra=_allowed(PROXY_PROVIDERS))
    base_url:        str = Field(examples=["https://api.openai.com/v1"], description="Endpoint the proxy forwards to.")
    api_key_masked:  str | None = Field(examples=["sk-a...mnop"], description="Masked provider key, or null when the provider needs none.")
    default_model:   str = Field(examples=["gpt-4o"], description="Used when a chat request omits `model`. A request may name its own as `provider/model`; with neither, the request is refused.")
    timeout_seconds: int = Field(examples=[60], description="Seconds the proxy waits for the provider before answering `504`.")
    created_at:      str | None = Field(examples=["2026-08-26T09:05:12.004Z"], description="ISO-8601 UTC with a Z suffix.")
    updated_at:      str | None = Field(examples=["2026-08-26T14:22:31.482Z"], description="ISO-8601 UTC with a Z suffix.")


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
    role:    str = Field(description="Always `assistant` on a response.", json_schema_extra=_allowed(CHAT_RESPONSE_ROLES))
    content: str = Field(description="The reply, after the output guard has run. Sanitized in place when it was rewritten.")


class ChatChoice(BaseModel):
    index:         int = Field(description="Always 0: this proxy returns a single choice.")
    message:       ChatMessage = Field(description="The assistant turn. Its content is what the output guard released.")
    finish_reason: str | None = Field(description="Passed through from the provider, for example `stop`.")


class ChatCompletionMeta(BaseModel):
    """The opt-in `wrapsec` block. Present only with `X-WrapSec-Inline-Meta:
    true`; the same values are always available on the response headers."""

    trace_id:             str = Field(examples=["req_2c31dee1bfda40a0b178c932d659f039"], description="The scan's identifier, the same value the `wrapsec-` prefix on `id` carries.")
    decision:             str = Field(description="Verdict on the input. A blocked input never reaches this body.", json_schema_extra=_allowed(CHAT_META_DECISIONS))
    input_primary_reason: str = Field(description="Dominant reason behind the verdict on the prompt.", json_schema_extra=_allowed(PRIMARY_REASONS))
    input_confidence:     float = Field(examples=[0.91], description="Confidence in the verdict on the prompt, 0.0-1.0.")
    input_was_sanitized:  bool = Field(description="True when the prompt was rewritten before being forwarded. A flag, not the text: the rewritten prompt is `input_sanitized` on the read-back models, and this block never carries it.")
    output_decision:      str | None = Field(description="Verdict on the reply. A blocked reply never reaches this body.", json_schema_extra=_allowed(CHAT_META_DECISIONS))
    output_was_sanitized: bool = Field(description="True when the reply was rewritten before being returned. A flag, not the text: the rewritten reply is `output_sanitized` on the read-back models, and this block never carries it.")
    execution_status:     str = Field(description="How the call ended. A body carrying this block is a success; a failure is returned as an error instead.", json_schema_extra=_allowed(CHAT_META_STATUSES))
    provider:             str | None = Field(description="Which provider served the call.", json_schema_extra=_allowed(PROXY_PROVIDERS))
    model:                str | None = Field(description="The model the provider reported using.")
    total_latency_ms:     int = Field(examples=[468], description="End to end, including detection on both sides.")


class ChatCompletionResponse(BaseModel):
    """OpenAI-compatible chat completion.

    Compatible, not equivalent: see the module note above for what this
    implementation omits and adds.
    """

    id:      str = Field(examples=["wrapsec-req_2c31dee1bfda40a0b178c932d659f039"], description="`wrapsec-{trace_id}`, not the provider's completion id.")
    object:  str = Field(description="Always `chat.completion`.", json_schema_extra=_allowed(CHAT_OBJECT))
    model:   str = Field(examples=["gpt-4o"], description="The model the provider reported using.")
    choices: list[ChatChoice] = Field(description="Always a single choice; this proxy does not return alternatives.")

    usage: dict[str, Any] | None = Field(
        default     = None,
        description = "The provider's own token counts, passed through when it sent them; absent otherwise. Observability only.",
    )
    wrapsec: ChatCompletionMeta | None = Field(
        default     = None,
        description = "Present only when the caller sets `X-WrapSec-Inline-Meta: true`.",
    )


class OpenAIErrorDetail(BaseModel):
    message: str = Field(description="Human-readable summary. The provider's own error text is never echoed here.")
    type:    str = Field(examples=["invalid_request_error"], description="OpenAI error family, for example `invalid_request_error`.")
    code:    str = Field(examples=["input_blocked"], description="Stable code, for example `input_blocked` or `invalid_model_format`.")


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

    error:   OpenAIErrorDetail = Field(description="The failure, in the shape an OpenAI client expects.")
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

    trace_id:        str = Field(examples=["req_2c31dee1bfda40a0b178c932d659f039"], description="Identifier of this scan.")
    timestamp:       str = Field(examples=["2026-08-26T14:22:31.482Z"], description="ISO-8601 UTC with a Z suffix.")
    tenant_id:       str | None = Field(examples=["8f14e45f-ceea-467a-9f2b-3c1a7d05e9b4"], description="Owning tenant.")
    decision:        str = Field(description="ALLOW, SANITIZE or BLOCK for the input scan.", json_schema_extra=_allowed(DECISIONS))
    output_decision: str | None = Field(description="Verdict on the model's reply. Null unless this turn went through the proxy.", json_schema_extra=_allowed(DECISIONS))
    provider:        str | None = Field(description="Null unless this turn went through the proxy.", json_schema_extra=_allowed(PROXY_PROVIDERS))
    model:           str | None = Field(examples=["gpt-4o"], description="Null unless this turn went through the proxy.")
    primary_reason:  str | None = Field(description="Dominant reason, null if none applied.", json_schema_extra=_allowed(PRIMARY_REASONS))
    risk_score:      float = Field(examples=[0.86], description="Aggregate risk, 0.0-1.0.")
    confidence:      float | None = Field(examples=[0.91], description="Confidence in the decision, 0.0-1.0.")
    confidence_band: str | None = Field(description="LOW, MEDIUM or HIGH.", json_schema_extra=_allowed(CONFIDENCE_BANDS))
    threats:         list[str] = Field(examples=[["PROMPT_INJECTION"]], description="Threat categories detected.")
    input_hash:      str = Field(examples=["sha256:9f2c4a1e7b3d5086af41c9d2e6b70835154cf9a2d7e0b6134c8fa259e7d3b041"], description="Hash of the scanned input; the input itself is not stored here.")
    detection_mode:  str = Field(description="`fast` runs the cheap layers; `full` adds the LLM detector.", json_schema_extra=_allowed(DETECTION_MODES))
    execution_mode:  str = Field(description="scan_only or proxy.", json_schema_extra=_allowed(EXECUTION_MODES))
    latency_ms:      float = Field(examples=[41.2], description="Detection time for this scan.")
    key_id:          str | None = Field(examples=["key:key_3f9a1c7d2e40"], description="API key the request was made with.")
    dept_id:         str | None = Field(examples=["2b7e1516-28ae-4d2a-a6ab-f7158809cf4f"], description="Owning department.")
    dept_name:       str | None = Field(description="Resolved name; null when the department no longer exists.")
    app_id:          str | None = Field(examples=["6bc1bee2-2e40-4b0f-9f1a-1e031fa8088a"], description="Owning application; null when the key is not application-scoped.")
    app_name:        str | None = Field(description="Resolved name; null when the application no longer exists.")
    user_id:         str | None = Field(description="Caller-supplied end-user identifier from the request metadata. Never an authorization input.")
    source:          str | None = Field(description="Caller-supplied label from the request metadata. Free text, and never an authorization input.")
    ip_address:      str | None = Field(examples=["203.0.113.42"], description="Client address as recorded when the request was scanned.")
    attribution_verified: bool = Field(description="Always false today: both writers set it literally and nothing updates it. Do not branch on it.")
    policy_source:   str | None = Field(description="Which policy layer resolved the decision, or `cache` for a cache hit.", json_schema_extra=_allowed(POLICY_SOURCES))
    input_length:    int = Field(description="Characters scanned.")
    severity:        str = Field(description="Risk level of the recorded decision.", json_schema_extra=_allowed(SEVERITIES))
    session_id:      str | None = Field(examples=["sess_9f31c02b"], description="Caller-supplied correlation; never an authorization input.")
    turn_index:      int | None = Field(description="Zero-based position within the session, as the caller supplied it.")
    run_id:          str | None = Field(examples=["run_4d81aa27"], description="Caller-supplied identifier grouping one agent run; its turns read back via GET /v1/agent-runs/{run_id}.")
    input_source:    str = Field(description="Declared provenance, for example `user_prompt` or `retrieved_document`.", json_schema_extra=_allowed(INPUT_SOURCES))
    record_hash:     str | None = Field(examples=["4b8d1f60c27ae9531d0fa4c8e7b25396081decaf35176e2b9c40af8d61e3752c"], description="Hash-chain value for this row.")
    prev_hash:       str | None = Field(examples=["e07c3a95124fb86d0e51937ac2648bd7f395021ce8ab4d76195f0c3e28ad641b"], description="Preceding row's hash. Null for the first row in a tenant's chain.")


class AgentRunResponse(BaseModel):
    """A run's scans as an ordered timeline (turn_index, then time).

    An unknown or out-of-scope run_id is not an error: it returns this same
    envelope with `count: 0` and an empty `turns`, which is what keeps one
    tenant's run ids from being probed against another's.
    """

    run_id: str = Field(examples=["run_4d81aa27"], description="Echoed back exactly as requested.")
    count:  int = Field(description="Number of turns returned, bounded by `limit`.")
    turns:  list[AuditItem] = Field(description="The run's scans in timeline order. Empty when the run is unknown or out of the caller's scope, which is not an error.")


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
    category: str = Field(description="Threat category, for example PROMPT_INJECTION.", json_schema_extra=_allowed(THREAT_CATEGORIES))
    count:    int = Field(description="Occurrences within the filtered range.")


class SeverityCounts(BaseModel):
    """Always all four keys, zero-filled. A severity absent from the range is a
    zero rather than a missing key, so a dashboard needs no defaulting."""

    CRITICAL: int = Field(description="Matching requests recorded at this risk level.")
    HIGH:     int = Field(description="Matching requests recorded at this risk level.")
    MEDIUM:   int = Field(description="Matching requests recorded at this risk level.")
    LOW:      int = Field(description="Matching requests recorded at this risk level.")


class AuditStatsResponse(BaseModel):
    """Aggregates over the filtered range.

    An empty range returns this same shape with every count and rate zeroed --
    the handler has a separate zero branch precisely so the contract does not
    change when there is nothing to aggregate.

    Counts sit alongside rates deliberately: reconstructing a count from
    `rate * total` drifts by one against `GET /v1/audit/logs?decision=BLOCK`,
    because the rate is rounded to four decimals.
    """

    period_from:     str = Field(examples=["2026-08-26T00:00:00.000Z"], description="Start of the range, echoed from the query or defaulted to now.")
    period_to:       str = Field(examples=["2026-08-26T23:59:59.999Z"], description="End of the range, echoed from the query or defaulted to now.")
    total_requests:  int = Field(description="Requests matching the range and filters.")
    block_count:     int = Field(description="Requests blocked. Prefer this to rate times total, which drifts once the rate is rounded.")
    sanitize_count:  int = Field(description="Requests sanitized. Prefer this to rate times total, which drifts once the rate is rounded.")
    allow_count:     int = Field(description="Requests allowed. Prefer this to rate times total, which drifts once the rate is rounded.")
    block_rate:      float = Field(examples=[0.0412], description="Fraction of matching requests blocked, rounded to 4 decimals.")
    sanitize_rate:   float = Field(examples=[0.1038], description="Fraction of matching requests sanitized, rounded to 4 decimals.")
    allow_rate:      float = Field(examples=[0.855], description="Fraction of matching requests allowed, rounded to 4 decimals.")
    avg_latency_ms:  float = Field(examples=[38.71], description="Mean detection time across matching requests.")
    p95_latency_ms:  float = Field(examples=[96.4], description="95th percentile, interpolated on PostgreSQL.")
    avg_risk:        float = Field(examples=[0.1873], description="Mean aggregate risk across matching requests, 0.0-1.0.")
    top_threats:     list[TopThreat] = Field(description="Most frequent categories first; empty when nothing matched.")
    severity_counts: SeverityCounts = Field(description="How many matching requests fell into each risk level.")


# ── GET /v1/ai/requests/{trace_id} ───────────────────────────────────────────


class RecordAttribution(BaseModel):
    tenant_id:            str | None = Field(examples=["8f14e45f-ceea-467a-9f2b-3c1a7d05e9b4"], description="Owning tenant.")
    dept_id:              str | None = Field(examples=["2b7e1516-28ae-4d2a-a6ab-f7158809cf4f"], description="Owning department.")
    dept_name:            str | None = Field(description="Resolved department name; null when the lookup found nothing.")
    app_id:               str | None = Field(examples=["6bc1bee2-2e40-4b0f-9f1a-1e031fa8088a"], description="Owning application; null when the key is not application-scoped.")
    app_name:             str | None = Field(description="Resolved application name; null when the lookup found nothing.")
    source:               str | None = Field(description="Caller-supplied label from the request metadata. Free text, and never an authorization input.")
    user_id:              str | None = Field(description="Caller-supplied end-user identifier from the request metadata. Never an authorization input.")
    key_id:               str | None = Field(examples=["key:key_3f9a1c7d2e40"], description="API key the request was made with.")
    ip_address:           str | None = Field(examples=["203.0.113.42"], description="Client address as recorded when the request was scanned.")
    user_agent:           str | None = Field(description="Client user agent as recorded when the request was scanned.")
    attribution_verified: bool = Field(description="Always false today: both writers set it literally and nothing updates it. Do not branch on it.")


class RecordProcessing(BaseModel):
    latency_ms:     float | None = Field(examples=[41.2], description="Detection time for this scan.")
    llm_invoked:    bool | None = Field(description="Whether the LLM detector ran.")
    detection_mode: str | None = Field(description="`fast` runs the cheap layers; `full` adds the LLM detector.", json_schema_extra=_allowed(DETECTION_MODES))
    execution_mode: str | None = Field(description="scan_only or proxy.", json_schema_extra=_allowed(EXECUTION_MODES))
    policy_source:  str | None = Field(description="Which policy layer resolved the decision, or `cache` for a cache hit.", json_schema_extra=_allowed(POLICY_SOURCES))


class RecordProxyDetail(BaseModel):
    """Proxy lifecycle, joined from `proxy_interactions`. Present only for a
    request executed in proxy mode."""

    provider:              str | None = Field(description="Null when the request never reached a provider.", json_schema_extra=_allowed(PROXY_PROVIDERS))
    model:                 str | None = Field(examples=["gpt-4o"], description="Model the provider reported using.")
    provider_latency_ms:   int | None = Field(examples=[412], description="Provider time only. Null when no call was made.")
    total_latency_ms:      int | None = Field(examples=[468], description="End to end, including detection on both sides.")
    execution_status:      str | None = Field(description="How the proxied call ended.", json_schema_extra=_allowed(EXECUTION_STATUSES))
    input_primary_reason:  str | None = Field(description="Dominant reason behind the verdict on the prompt.", json_schema_extra=_allowed(PRIMARY_REASONS))
    input_confidence:      float | None = Field(examples=[0.91], description="Confidence in the verdict on the prompt, 0.0-1.0.")
    input_threats:         list[str] = Field(examples=[["PROMPT_INJECTION"]], description="Threat categories detected in the prompt.")
    input_attack_type:     str | None = Field(description="The first threat category detected in the prompt, or null when none was.", json_schema_extra=_allowed(THREAT_CATEGORIES))
    input_raw:             str | None = Field(description="Prompt as received. Null when storage mode did not retain it.")
    input_sanitized:       str | None = Field(description="Prompt after redaction. Null when nothing was rewritten.")
    output_decision:       str | None = Field(description="Verdict on the reply. Null when there was no reply to guard.", json_schema_extra=_allowed(DECISIONS))
    output_primary_reason: str | None = Field(description="Dominant reason behind the verdict on the reply.", json_schema_extra=_allowed(PRIMARY_REASONS))
    output_confidence:     float | None = Field(examples=[0.12], description="Confidence in the verdict on the reply, 0.0-1.0.")
    output_threats:        list[str] = Field(examples=[[]], description="Threat categories detected in the reply.")
    output_raw:            str | None = Field(description="Provider reply as received. Null when storage mode did not retain it.")
    output_sanitized:      str | None = Field(description="Reply after redaction. Null when nothing was rewritten.")
    behavior_flag:         str | None = Field(description="No writer sets this, so it is always null.")
    output_flags:          Any | None = Field(description="No writer sets this, so it is always null.")


class RequestRecordResponse(BaseModel):
    trace_id:       str = Field(examples=["req_2c31dee1bfda40a0b178c932d659f039"], description="Identifier of the scan being read back.")
    timestamp:      str = Field(examples=["2026-08-26T14:22:31.482Z"], description="ISO-8601 UTC with a Z suffix.")
    execution_mode: str | None = Field(description="How the request ran.", json_schema_extra=_allowed(EXECUTION_MODES))
    is_proxy:       bool = Field(description="True when `execution_mode` is `proxy`. The same fact, as a boolean.")
    severity:       str | None = Field(description="Risk level of the recorded decision.", json_schema_extra=_allowed(SEVERITIES))
    attribution:    RecordAttribution = Field(description="Who and what the request was attributed to.")

    decision:        str = Field(description="ALLOW, SANITIZE or BLOCK.", json_schema_extra=_allowed(DECISIONS))
    risk_score:      float | None = Field(examples=[0.86], description="Aggregate risk, 0.0-1.0.")
    primary_reason:  str | None = Field(description="Dominant reason, null if none applied.", json_schema_extra=_allowed(PRIMARY_REASONS))
    confidence:      float | None = Field(examples=[0.91], description="Confidence in the decision, 0.0-1.0.")
    confidence_band: str | None = Field(description="LOW, MEDIUM or HIGH.", json_schema_extra=_allowed(CONFIDENCE_BANDS))
    threats:         list[str] = Field(examples=[["PROMPT_INJECTION"]], description="Threat categories detected.")

    input_hash:   str = Field(examples=["sha256:9f2c4a1e7b3d5086af41c9d2e6b70835154cf9a2d7e0b6134c8fa259e7d3b041"], description="Hash of the scanned input; the input itself is never stored here.")
    input_length: int = Field(description="Characters scanned.")

    run_id:       str | None = Field(examples=["run_4d81aa27"], description="Caller-supplied agent-run correlation; never an authorization input.")
    session_id:   str | None = Field(examples=["sess_9f31c02b"], description="Caller-supplied correlation; never an authorization input.")
    turn_index:   int | None = Field(description="Zero-based position within the session, as the caller supplied it.")
    input_source: str | None = Field(description="Declared provenance, for example `user_prompt` or `retrieved_document`.", json_schema_extra=_allowed(INPUT_SOURCES))

    detection_scores: dict[str, float] = Field(examples=[{"rule": 0.86, "ml": 0.74, "llm": 0.31}], 
        description="Per-detector scores as persisted. EMPTY for a caller that may not read layer scores -- "
                    "the key stays present so consumers need no special case.",
    )
    guardrail_scores: dict[str, float] = Field(examples=[{"pii": 0.0}], 
        description="Guardrail scores as persisted. Empty under the same restriction as detection_scores.",
    )

    processing: RecordProcessing = Field(description="Timing, modes, and which policy layer resolved the decision.")
    proxy:      RecordProxyDetail | None = Field(
        default     = None,
        description = "Proxy lifecycle detail. Absent for a scan-only request.",
    )
