from dataclasses import dataclass, field
from datetime import datetime
from domain.enums import DecisionType, ThreatCategory, DetectionMode, ExecutionMode, get_risk_level, RiskLevel
from domain.value_objects.risk_score import RiskScore
from domain.value_objects.trace_id import TraceId


@dataclass
class LayerScores:
    rule_score: float = 0.0
    ml_score:   float = 0.0
    llm_score:  float = 0.0
    pii_score:  float = 0.0

    def as_dict(self) -> dict:
        return {
            "rule_score": self.rule_score,
            "ml_score":   self.ml_score,
            "llm_score":  self.llm_score,
            "pii_score":  self.pii_score,
        }


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
    decided_at:      datetime              = field(default_factory=datetime.utcnow)

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