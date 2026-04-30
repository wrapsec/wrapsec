# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from pydantic import BaseModel, Field, model_validator
from domain.enums import DetectionMode, ExecutionMode
from errors.exceptions import StreamNotSupportedError, ModelRequiredError, WrapSecError


class RequestMetadataSchema(BaseModel):
    # tenant_id intentionally removed — derived from API key only
    # Allowing caller-provided tenant_id enables spoofing
    source:  str | None = None
    user_id: str | None = None


class RequestContextSchema(BaseModel):
    user_role:   str | None = None
    sensitivity: str | None = None  # low | medium | high


class RequestOptionsSchema(BaseModel):
    stream: bool = False
    debug:  bool = False


class AIRequestSchema(BaseModel):
    input:          str                       = Field(..., min_length=1, max_length=8000)
    # 8,000 chars ≈ 2,000 tokens (safe for all languages including CJK)
    # Full per-model token counting with tiktoken planned for V1.1
    detection_mode: DetectionMode             = DetectionMode.FAST
    execution_mode: ExecutionMode             = ExecutionMode.SCAN_ONLY
    model:          str | None                = None
    metadata:       RequestMetadataSchema     = Field(default_factory=RequestMetadataSchema)
    context:        RequestContextSchema      = Field(default_factory=RequestContextSchema)
    options:        RequestOptionsSchema      = Field(default_factory=RequestOptionsSchema)

    @model_validator(mode="after")
    def validate_mode_combinations(self) -> "AIRequestSchema":
        # stream only valid in proxy mode
        if self.options.stream and self.execution_mode == ExecutionMode.SCAN_ONLY:
            raise StreamNotSupportedError()

        # model required in proxy mode
        if self.execution_mode == ExecutionMode.PROXY and not self.model:
            raise ModelRequiredError()

        # model field ignored in scan_only mode — clear it
        if self.execution_mode == ExecutionMode.SCAN_ONLY:
            self.model = None

        # Heuristic token limit — safe for all languages including CJK
        # Conservative estimate: 1 token ≈ 2 chars
        # English: actual ~4 chars/token → estimate is 2x conservative (safe)
        # CJK:     actual ~1 char/token  → estimate is 2x conservative (safe)
        # This ensures we never undercount tokens regardless of language
        # Full per-model tiktoken counting planned for V1.1
        import math
        estimated_tokens = math.ceil(len(self.input) / 2)
        if estimated_tokens > 4000:
            raise ValueError(
                f"Input exceeds estimated token limit of 4000 "
                f"(estimated {estimated_tokens} tokens from {len(self.input)} characters). "
                f"Maximum input is 8000 characters."
            )

        return self

    model_config = {"use_enum_values": True, "populate_by_name": True}