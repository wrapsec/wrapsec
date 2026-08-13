# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from dataclasses import dataclass, field
from datetime import datetime, timezone

from domain.enums import DecisionType, DetectionMode, ExecutionMode, ThreatCategory
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
    created_at:      datetime    = field(default_factory=lambda: datetime.now(timezone.utc))