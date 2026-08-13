# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from pydantic import BaseModel


class ProcessingSchema(BaseModel):
    latency_ms:     float
    llm_invoked:    bool
    detection_mode: str
    execution_mode: str


class LayerScoresSchema(BaseModel):
    rule_score:      float
    ml_score:        float
    llm_score:       float
    layer_decisions: dict[str, str]


class GatewayResponseSchema(BaseModel):
    trace_id:        str
    decision:        str
    risk_score:      float
    threats:         list[str]
    sanitized_input: str | None = None
    output:          str | None = None
    debug:           LayerScoresSchema | None = None
    processing:      ProcessingSchema


class ErrorDetailSchema(BaseModel):
    code:     str
    message:  str
    trace_id: str


class ErrorResponseSchema(BaseModel):
    error: ErrorDetailSchema