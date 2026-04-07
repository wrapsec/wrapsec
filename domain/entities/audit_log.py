from dataclasses import dataclass, field
from datetime import datetime
from domain.enums import DecisionType, ThreatCategory, DetectionMode, ExecutionMode
from domain.value_objects.trace_id import TraceId


@dataclass
class AuditLog:
    trace_id:        TraceId
    decision:        DecisionType
    risk_score:      float
    threats:         list[ThreatCategory]
    input_hash:      str
    detection_mode:  DetectionMode
    execution_mode:  ExecutionMode
    llm_invoked:     bool
    latency_ms:      float
    tenant_id:       str | None  = None
    source:          str | None  = None
    user_id:         str | None  = None
    created_at:      datetime    = field(default_factory=datetime.utcnow)