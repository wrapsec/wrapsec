# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec response models.

All models in __all__ are stable public API.
Field names follow Python snake_case convention.

Spec reference: Section 4 (Public API Surface), Section 5 (Field Naming Convention)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScanResult:
    """
    Result of a single scan request (POST /v1/ai/request).

    decision        : "ALLOW" | "BLOCK" | "SANITIZE"
    risk_score      : overall risk level (0.0-1.0) - threshold used for decision
    confidence      : detection model confidence (0.0-1.0), distinct from risk_score
    primary_reason  : detector that triggered the decision
    sanitized_input : cleaned input, only present when decision == "SANITIZE"
    output          : LLM response, only present when execution_mode == "proxy"
    execution_mode  : "scan_only" | "proxy"
    """

    decision:        str
    primary_reason:  str
    confidence:      float
    confidence_band: str
    trace_id:        str
    threats:         list[str]
    latency_ms:      float
    risk_score:            float       = 0.0
    execution_mode:        str         = "scan_only"
    sanitization_applied:  bool        = False
    sanitized_input:       str | None  = None
    output:                str | None  = None
    # v1.7.0 Security Assessment: the always-present structured verdict
    # (decision, reasons, threats, confidence, and per-layer contributions).
    assessment:            dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        processing = data.get("processing") or {}
        return cls(
            decision             = data["decision"],
            primary_reason       = data["primary_reason"],
            risk_score           = float(data.get("risk_score", 0.0)),
            confidence           = float(data.get("confidence", 0.0)),
            confidence_band      = data.get("confidence_band", "LOW"),
            trace_id             = data.get("trace_id", ""),
            threats              = data.get("threats") or [],
            latency_ms           = float(
                data["latency_ms"]
                if data.get("latency_ms") is not None
                else processing.get("latency_ms", 0.0)
            ),
            execution_mode       = processing.get("execution_mode", "scan_only"),
            sanitization_applied = bool(data.get("sanitization_applied", False)),
            sanitized_input      = data.get("sanitized_input"),
            output               = data.get("output"),
            assessment           = data.get("assessment"),
        )

    @property
    def is_blocked(self) -> bool:
        return self.decision == "BLOCK"

    @property
    def is_sanitized(self) -> bool:
        return self.decision == "SANITIZE"

    @property
    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def is_system_error(self) -> bool:
        return self.primary_reason == "SYSTEM_ERROR"

    @property
    def is_proxy(self) -> bool:
        return self.execution_mode == "proxy"


@dataclass(frozen=True)
class BatchItemResult:
    """
    One item's outcome within a batch scan (POST /v1/ai/scan-batch).

    id         : the caller-supplied reference echoed back (None if not given)
    trace_id   : this item's own scan trace_id (correlates to the audit trail)
    decision   : "ALLOW" | "BLOCK" | "SANITIZE"
    assessment : the structured security assessment for this item
    """

    id:         str | None
    trace_id:   str
    decision:   str
    assessment: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BatchItemResult":
        return cls(
            id         = data.get("id"),
            trace_id   = data.get("trace_id", ""),
            decision   = data.get("decision", ""),
            assessment = data.get("assessment"),
        )

    @property
    def is_blocked(self) -> bool:
        return self.decision == "BLOCK"

    @property
    def is_sanitized(self) -> bool:
        return self.decision == "SANITIZE"

    @property
    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"


@dataclass(frozen=True)
class BatchScanResult:
    """
    Result of a batch scan (POST /v1/ai/scan-batch).

    count   : number of items scanned
    summary : aggregate over the batch - blocked / sanitized / allowed counts,
              highest_risk (+ highest_risk_item id), and the union of threats
    results : per-item outcomes, in the same order as the inputs
    """

    count:   int
    summary: dict[str, Any]
    results: list[BatchItemResult]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BatchScanResult":
        return cls(
            count   = int(data.get("count", 0)),
            summary = data.get("summary") or {},
            results = [BatchItemResult.from_dict(r) for r in data.get("results", [])],
        )

    def __iter__(self):
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    @property
    def blocked(self) -> list["BatchItemResult"]:
        return [r for r in self.results if r.is_blocked]

    @property
    def highest_risk(self) -> float | None:
        return self.summary.get("highest_risk")


@dataclass(frozen=True)
class AuditLog:
    """
    A single audit log entry returned from GET /v1/audit/logs.

    risk_score      : overall risk level (0.0-1.0), distinct from confidence
    confidence      : detection model confidence (0.0-1.0)
    severity        : CRITICAL | HIGH | MEDIUM | LOW (SIEM triage level)
    output_decision : scan decision on the LLM output (proxy mode only)
    provider/model  : LLM provider and model used (proxy mode only)
    """

    # Core identity
    trace_id:             str
    created_at:           str

    # Decision
    decision:             str
    primary_reason:       str
    risk_score:           float
    confidence:           float
    confidence_band:      str
    threats:              list[str]
    severity:             str | None

    # Performance
    latency_ms:           float
    input_length:         int

    # Attribution
    key_id:               str | None
    dept_id:              str | None
    dept_name:            str | None
    app_id:               str | None
    app_name:             str | None
    user_id:              str | None
    source:               str | None
    ip_address:           str | None
    tenant_id:            str | None
    attribution_verified: bool

    # Processing metadata
    detection_mode:       str | None
    execution_mode:       str | None
    policy_source:        str | None
    input_hash:           str | None

    # Proxy mode - None for scan_only requests
    output_decision:      str | None = None
    provider:             str | None = None
    model:                str | None = None

    # ML detection metadata
    model_version:        str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditLog":
        return cls(
            trace_id             = data.get("trace_id", ""),
            created_at           = data.get("timestamp", data.get("created_at", "")),
            decision             = data.get("decision", ""),
            primary_reason       = data.get("primary_reason", ""),
            # risk_score and confidence are separate - never substitute one for the other
            risk_score           = float(data.get("risk_score", 0.0)),
            confidence           = float(data.get("confidence", 0.0)),
            confidence_band      = data.get("confidence_band", ""),
            threats              = data.get("threats") or [],
            severity             = data.get("severity"),
            latency_ms           = float(data.get("latency_ms", 0.0)),
            input_length         = int(data.get("input_length", 0)),
            key_id               = data.get("key_id"),
            dept_id              = data.get("dept_id"),
            dept_name            = data.get("dept_name"),
            app_id               = data.get("app_id"),
            app_name             = data.get("app_name"),
            user_id              = data.get("user_id"),
            source               = data.get("source"),
            ip_address           = data.get("ip_address"),
            tenant_id            = data.get("tenant_id"),
            attribution_verified = bool(data.get("attribution_verified", False)),
            detection_mode       = data.get("detection_mode"),
            execution_mode       = data.get("execution_mode"),
            policy_source        = data.get("policy_source"),
            input_hash           = data.get("input_hash"),
            output_decision      = data.get("output_decision"),
            provider             = data.get("provider"),
            model                = data.get("model"),
            model_version        = data.get("model_version"),
        )


@dataclass(frozen=True)
class AuditStats:
    """
    Aggregated statistics returned from GET /v1/audit/stats.

    severity_counts breaks down requests by SIEM severity level:
        CRITICAL - guardrail blocks (PII, toxicity) or risk_score >= 0.9
        HIGH     - other blocks or SYSTEM_ERROR
        MEDIUM   - sanitized requests
        LOW      - allowed requests
    """

    total_requests:  int
    block_count:     int
    sanitize_count:  int
    allow_count:     int
    block_rate:      float
    avg_latency_ms:  float
    p95_latency_ms:  float
    top_threats:     list[dict[str, Any]]
    severity_counts: dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
    })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditStats":
        total      = int(data.get("total_requests", 0))
        block_rate = float(data.get("block_rate", 0.0))
        san_rate   = float(data.get("sanitize_rate", 0.0))
        allow_rate = float(data.get("allow_rate", 0.0))
        return cls(
            total_requests  = total,
            block_count     = int(data.get("block_count",    round(total * block_rate))),
            sanitize_count  = int(data.get("sanitize_count", round(total * san_rate))),
            allow_count     = int(data.get("allow_count",    round(total * allow_rate))),
            block_rate      = block_rate,
            avg_latency_ms  = float(data.get("avg_latency_ms", 0.0)),
            p95_latency_ms  = float(data.get("p95_latency_ms", 0.0)),
            top_threats     = data.get("top_threats") or [],
            severity_counts = data.get("severity_counts") or {
                "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
            },
        )


__all__ = [
    "ScanResult",
    "BatchItemResult",
    "BatchScanResult",
    "AuditLog",
    "AuditStats",
]
