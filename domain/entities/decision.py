# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from dataclasses import dataclass, field
from datetime import datetime, timezone
from domain.enums import DecisionType, ThreatCategory, DetectionMode, ExecutionMode, get_risk_level, RiskLevel
from domain.value_objects.risk_score import RiskScore
from domain.value_objects.trace_id import TraceId


class LayerScores:
    """
    Open-ended per-layer score bag.

    Historically a dataclass with five fixed fields (rule_score, ml_score,
    llm_score, pii_score, toxicity_score). v1.1.0 (B2) rewrites the backing
    store as `dict[str, float]` so downstream releases can add new keys --
    multi-class transformer categories, MCP-added detectors, per-category
    toxicity -- without touching the shared entity.

    Backward compatibility:
      - Attribute access (`layer_scores.rule_score`) still works; missing
        keys return 0.0, matching the old dataclass defaults.
      - `as_dict()` still returns a plain dict, but now includes every
        key that was written, not just the original five.

    New usage:
      - `layer_scores["transformer_jailbreak"] = 0.87`
      - `for name, score in layer_scores.items(): ...`
    """

    __slots__ = ("_scores",)

    _CORE_KEYS = ("rule_score", "ml_score", "llm_score", "pii_score", "toxicity_score")

    def __init__(self, **scores: float) -> None:
        self._scores: dict[str, float] = {k: float(v) for k, v in scores.items()}

    def __getattr__(self, name: str) -> float:
        if name.startswith("_"):
            raise AttributeError(name)
        return float(self._scores.get(name, 0.0))

    def __getitem__(self, key: str) -> float:
        return float(self._scores.get(key, 0.0))

    def __setitem__(self, key: str, value: float) -> None:
        self._scores[key] = float(value)

    def __contains__(self, key: str) -> bool:
        return key in self._scores

    def __iter__(self):
        return iter(self._scores)

    def __len__(self) -> int:
        return len(self._scores)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, LayerScores):
            return self._scores == other._scores
        if isinstance(other, dict):
            return self._scores == other
        return NotImplemented

    def __repr__(self) -> str:
        return f"LayerScores({self._scores!r})"

    def keys(self):
        return self._scores.keys()

    def values(self):
        return self._scores.values()

    def items(self):
        return self._scores.items()

    def update(self, other: "LayerScores | dict[str, float]") -> None:
        if isinstance(other, LayerScores):
            self._scores.update(other._scores)
        else:
            for k, v in other.items():
                self._scores[k] = float(v)

    def as_dict(self) -> dict[str, float]:
        """
        Return a defensive copy. Callers that need every-key-present output
        (e.g. legacy consumers of the five core keys) can wrap this via
        `{k: scores.get(k, 0.0) for k in LayerScores._CORE_KEYS}`.
        """
        return dict(self._scores)


@dataclass
class GatewayDecision:
    trace_id:        TraceId
    decision:        DecisionType
    risk_score:      RiskScore
    threats:         list[ThreatCategory]  = field(default_factory=list)
    sanitized_input: str | None            = None
    output:          str | None            = None
    layer_scores:    LayerScores | None    = None
    llm_invoked:     bool                  = False
    detection_mode:  DetectionMode         = DetectionMode.FAST
    execution_mode:  ExecutionMode         = ExecutionMode.SCAN_ONLY
    latency_ms:      float                 = 0.0
    primary_reason:  str | None            = None
    confidence:      float | None          = None
    confidence_band: str | None            = None
    decided_at:      datetime              = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def risk_level(self) -> RiskLevel:
        return get_risk_level(self.risk_score.value)

    def is_blocked(self) -> bool:
        return self.decision == DecisionType.BLOCK

    def is_sanitized(self) -> bool:
        return self.decision == DecisionType.SANITIZE

    def is_allowed(self) -> bool:
        return self.decision == DecisionType.ALLOW

    def has_threats(self) -> bool:
        return len(self.threats) > 0
