from pydantic import BaseModel
from datetime import datetime


class AuditLogItemSchema(BaseModel):
    trace_id:       str
    timestamp:      datetime
    tenant_id:      str | None
    decision:       str
    risk_score:     float
    threats:        list[str]
    input_hash:     str
    detection_mode: str
    execution_mode: str
    latency_ms:     float


class AuditLogsResponseSchema(BaseModel):
    total: int
    items: list[AuditLogItemSchema]


class ThreatCountSchema(BaseModel):
    category: str
    count:    int


class AuditStatsResponseSchema(BaseModel):
    period_from:     datetime
    period_to:       datetime
    total_requests:  int
    block_rate:      float
    sanitize_rate:   float
    allow_rate:      float
    avg_latency_ms:  float
    p95_latency_ms:  float
    top_threats:     list[ThreatCountSchema]


class RetrieveRequestResponseSchema(BaseModel):
    trace_id:       str
    timestamp:      datetime
    metadata:       dict
    decision:       str
    risk_score:     float
    threats:        list[str]
    input_hash:     str
    processing:     dict