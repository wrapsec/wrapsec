"""
WrapSec response models.

All models in __all__ are stable public API.
Field names follow Python snake_case convention.

Spec reference: Section 4 (Public API Surface), Section 5 (Field Naming Convention)

Field mapping (API → Python):
  decision        → decision
  primary_reason  → primary_reason
  confidence      → confidence
  confidence_band → confidence_band
  trace_id        → trace_id
  sanitized_input → sanitized_input
  threats         → threats
  latency_ms      → latency_ms
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScanResult:
    """
    Result of a single scan request.

    decision is always one of: "ALLOW", "BLOCK", "SANITIZE"
    primary_reason identifies which detector triggered the decision.
    sanitized_input is None unless decision == "SANITIZE".
    """

    decision:        str
    primary_reason:  str
    confidence:      float
    confidence_band: str
    trace_id:        str
    threats:         list[str]
    latency_ms:      float
    sanitized_input: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        return cls(
            decision        = data["decision"],
            primary_reason  = data["primary_reason"],
            confidence      = float(data.get("confidence", 0.0)),
            confidence_band = data.get("confidence_band", "LOW"),
            trace_id        = data.get("trace_id", ""),
            threats         = data.get("threats") or [],
            latency_ms      = float(data.get("latency_ms", 0.0)),
            sanitized_input = data.get("sanitized_input"),
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


@dataclass(frozen=True)
class AuditLog:
    """
    A single audit log entry returned from GET /v1/audit/logs.
    """

    trace_id:        str
    decision:        str
    primary_reason:  str
    confidence:      float
    confidence_band: str
    threats:         list[str]
    latency_ms:      float
    input_length:    int
    key_id:          str | None
    dept_id:         str | None
    app_id:          str | None
    user_id:         str | None
    source:          str | None
    created_at:      str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditLog":
        return cls(
            trace_id        = data.get("trace_id", ""),
            decision        = data.get("decision", ""),
            primary_reason  = data.get("primary_reason", ""),
            confidence      = float(data.get("confidence", 0.0)),
            confidence_band = data.get("confidence_band", ""),
            threats         = data.get("threats") or [],
            latency_ms      = float(data.get("latency_ms", 0.0)),
            input_length    = int(data.get("input_length", 0)),
            key_id          = data.get("key_id"),
            dept_id         = data.get("dept_id"),
            app_id          = data.get("app_id"),
            user_id         = data.get("user_id"),
            source          = data.get("source"),
            created_at      = data.get("created_at", ""),
        )


@dataclass(frozen=True)
class AuditStats:
    """
    Aggregated statistics returned from GET /v1/audit/stats.
    """

    total_requests:  int
    block_count:     int
    sanitize_count:  int
    allow_count:     int
    block_rate:      float
    avg_latency_ms:  float
    p95_latency_ms:  float
    top_threats:     list[dict[str, Any]]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditStats":
        return cls(
            total_requests = int(data.get("total_requests", 0)),
            block_count    = int(data.get("block_count", 0)),
            sanitize_count = int(data.get("sanitize_count", 0)),
            allow_count    = int(data.get("allow_count", 0)),
            block_rate     = float(data.get("block_rate", 0.0)),
            avg_latency_ms = float(data.get("avg_latency_ms", 0.0)),
            p95_latency_ms = float(data.get("p95_latency_ms", 0.0)),
            top_threats    = data.get("top_threats") or [],
        )


__all__ = [
    "ScanResult",
    "AuditLog",
    "AuditStats",
]
