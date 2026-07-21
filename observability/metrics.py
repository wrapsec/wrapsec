# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from prometheus_client import (
    Counter, Histogram, Gauge,
    generate_latest, CONTENT_TYPE_LATEST,
    CollectorRegistry, REGISTRY,
)

# ── Request metrics ───────────────────────────────────────────
REQUEST_TOTAL = Counter(
    "wrapsec_requests_total",
    "Total requests processed by WrapSec",
    ["decision", "detection_mode", "execution_mode", "key_type"],
)

REQUEST_LATENCY = Histogram(
    "wrapsec_request_latency_ms",
    "End-to-end request latency in milliseconds",
    ["decision", "execution_mode"],
    buckets=[5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000],
)

# ── Security decision metrics ─────────────────────────────────
SYSTEM_ERRORS = Counter(
    "wrapsec_system_errors_total",
    "Total SYSTEM_ERROR decisions - detection pipeline failures requiring ops attention",
    ["execution_mode"],
)

BLOCKED_TOTAL = Counter(
    "wrapsec_blocked_total",
    "Total BLOCK decisions by primary reason",
    ["primary_reason", "execution_mode"],
)

SANITIZED_TOTAL = Counter(
    "wrapsec_sanitized_total",
    "Total SANITIZE decisions by primary reason",
    ["primary_reason", "execution_mode"],
)

# ── Threat metrics ────────────────────────────────────────────
THREAT_DETECTED = Counter(
    "wrapsec_threats_detected_total",
    "Total threats detected by category",
    ["category"],
)

# ── Proxy execution metrics ───────────────────────────────────
PROXY_EXECUTION = Counter(
    "wrapsec_proxy_execution_total",
    "Proxy mode requests by execution status",
    ["execution_status"],
    # execution_status: SUCCESS | BLOCKED | OUTPUT_BLOCKED | FAILED | TIMEOUT
)

PROXY_LATENCY = Histogram(
    "wrapsec_proxy_latency_ms",
    "Total proxy end-to-end latency in milliseconds",
    ["execution_status"],
    buckets=[100, 500, 1000, 2500, 5000, 10000, 30000, 60000, 120000],
)

# ── Layer metrics ─────────────────────────────────────────────
LAYER_SCORE = Histogram(
    "wrapsec_layer_score",
    "Detection score per layer",
    ["layer"],
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

# ── LLM metrics ───────────────────────────────────────────────
LLM_INVOCATIONS = Counter(
    "wrapsec_llm_invocations_total",
    "Total LLM invocations by provider and purpose",
    ["provider", "purpose"],  # purpose: detection | completion
)

LLM_LATENCY = Histogram(
    "wrapsec_llm_latency_ms",
    "LLM response latency in milliseconds",
    ["provider", "purpose"],
    buckets=[100, 500, 1000, 2500, 5000, 10000, 30000, 60000],
)

# ── Cache metrics ─────────────────────────────────────────────
CACHE_HITS = Counter(
    "wrapsec_cache_hits_total",
    "Total semantic cache hits",
)

CACHE_MISSES = Counter(
    "wrapsec_cache_misses_total",
    "Total semantic cache misses",
)

# ── Rate limit metrics ────────────────────────────────────────
# No key_type label - rate limiting runs before auth middleware,
# so key_type is not reliably known at this point.
RATE_LIMITED = Counter(
    "wrapsec_rate_limited_total",
    "Total requests rejected by rate limiting",
)


# ── Label allowlists - CRITICAL for cardinality safety ────────
# Only values in these sets are accepted as metric labels.
# Unexpected values are replaced with "unknown" to prevent:
#   1. Unbounded cardinality crashing Prometheus
#   2. User-supplied or engine-generated strings entering metrics
_VALID_DECISIONS        = frozenset({"ALLOW", "BLOCK", "SANITIZE"})
_VALID_DETECTION_MODES  = frozenset({"fast", "full"})
_VALID_EXECUTION_MODES  = frozenset({"scan_only", "proxy"})
_VALID_KEY_TYPES        = frozenset({"live", "trial"})
_VALID_PRIMARY_REASONS  = frozenset({
    "RULE_DETECTOR", "ML_DETECTOR", "LLM_DETECTOR",
    "PII_GUARDRAIL_BLOCK", "PII_GUARDRAIL_SANITIZE",
    "TOXICITY_GUARDRAIL_BLOCK",
    "NO_THREAT_DETECTED", "SYSTEM_ERROR",
})
_VALID_THREAT_CATEGORIES = frozenset({
    "PROMPT_INJECTION", "JAILBREAK", "PII", "DATA_EXFILTRATION",
    "MALICIOUS_INTENT", "TOXICITY",
})
_VALID_EXECUTION_STATUSES = frozenset({
    "SUCCESS", "BLOCKED", "OUTPUT_BLOCKED", "FAILED", "TIMEOUT",
})
_VALID_PROVIDERS = frozenset({"openai", "ollama", "groq", "custom", "unknown"})
_VALID_LAYERS    = frozenset({"rule", "ml", "llm"})


def _safe(value: str, allowed: frozenset, fallback: str = "unknown") -> str:
    """Return value if in allowlist, else fallback. Never lets arbitrary strings into labels."""
    return value if value in allowed else fallback


def record_request(
    decision:       str,
    detection_mode: str,
    execution_mode: str,
    latency_ms:     float,
    threats:        list[str],
    layer_scores:   dict | None = None,
    primary_reason: str | None = None,
    key_type:       str = "live",
) -> None:
    """Record metrics for a completed gateway request.

    All label values are validated against allowlists before use.
    Unknown values are replaced with 'unknown' - never raises.
    """
    safe_decision  = _safe(decision,       _VALID_DECISIONS,       "ALLOW")
    safe_det_mode  = _safe(detection_mode, _VALID_DETECTION_MODES, "fast")
    safe_exe_mode  = _safe(execution_mode, _VALID_EXECUTION_MODES, "scan_only")
    safe_key_type  = _safe(key_type,       _VALID_KEY_TYPES,       "live")
    safe_reason    = _safe(primary_reason or "", _VALID_PRIMARY_REASONS, "unknown")

    REQUEST_TOTAL.labels(
        decision       = safe_decision,
        detection_mode = safe_det_mode,
        execution_mode = safe_exe_mode,
        key_type       = safe_key_type,
    ).inc()

    REQUEST_LATENCY.labels(
        decision       = safe_decision,
        execution_mode = safe_exe_mode,
    ).observe(latency_ms)

    # Track SYSTEM_ERROR separately - ops health signal
    if primary_reason == "SYSTEM_ERROR":
        SYSTEM_ERRORS.labels(execution_mode=safe_exe_mode).inc()

    # Track BLOCK and SANITIZE by reason - validated reason only
    if safe_decision == "BLOCK" and safe_reason != "unknown":
        BLOCKED_TOTAL.labels(
            primary_reason = safe_reason,
            execution_mode = safe_exe_mode,
        ).inc()
    elif safe_decision == "SANITIZE" and safe_reason != "unknown":
        SANITIZED_TOTAL.labels(
            primary_reason = safe_reason,
            execution_mode = safe_exe_mode,
        ).inc()

    # Only record validated threat categories
    for threat in threats:
        safe_threat = _safe(threat, _VALID_THREAT_CATEGORIES)
        if safe_threat != "unknown":
            THREAT_DETECTED.labels(category=safe_threat).inc()

    if layer_scores:
        for layer, score in layer_scores.items():
            safe_layer = _safe(layer, _VALID_LAYERS)
            if safe_layer != "unknown":
                LAYER_SCORE.labels(layer=safe_layer).observe(score)


def record_proxy_request(
    execution_status: str,
    total_latency_ms: int,
    llm_invoked:      bool = False,
    provider:         str  = "unknown",
) -> None:
    """Record metrics for a completed proxy request.
    Provider is validated against allowlist - never accepts arbitrary strings.
    """
    safe_status   = _safe(execution_status, _VALID_EXECUTION_STATUSES, "unknown")
    safe_provider = _safe(provider.lower(), _VALID_PROVIDERS, "unknown")

    PROXY_EXECUTION.labels(execution_status=safe_status).inc()
    PROXY_LATENCY.labels(execution_status=safe_status).observe(total_latency_ms)

    if llm_invoked:
        LLM_INVOCATIONS.labels(provider=safe_provider, purpose="completion").inc()


def record_rate_limit() -> None:
    """Record a rate limit rejection.
    key_type intentionally omitted - rate limit runs before auth,
    so key_type is not reliably known at this point.
    """
    RATE_LIMITED.inc()


def get_metrics() -> tuple[bytes, str]:
    """Return Prometheus metrics in text format."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST