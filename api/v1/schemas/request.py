# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import math
from pydantic import BaseModel, Field, model_validator
from domain.enums import DetectionMode, ExecutionMode
from errors.exceptions import StreamNotSupportedError, ModelRequiredError, WrapSecError
from config.settings import get_settings


class RequestMetadataSchema(BaseModel):
    # tenant_id intentionally removed - derived from API key only
    # Allowing caller-provided tenant_id enables spoofing
    source:  str | None = None
    user_id: str | None = None


class RequestContextSchema(BaseModel):
    user_role:   str | None = None
    sensitivity: str | None = None  # low | medium | high


class RequestOptionsSchema(BaseModel):
    stream: bool = False
    debug:  bool = False


_SESSION_ID_PATTERN = r"^[A-Za-z0-9_.:\-]+$"
_SESSION_ID_DESC    = (
    "Caller-supplied conversation identifier that groups scans belonging to the "
    "same multi-turn interaction. Opaque string, max 200 chars, "
    "[A-Za-z0-9_.:-] only. Do NOT include PII (name, email, phone); use a "
    "hash, UUID, or other opaque identifier. v1 persists the field for future "
    "correlation; session-aware detection lands in a later release."
)
_RUN_ID_DESC = (
    "Caller-supplied identifier for one agent execution (which may span multiple "
    "gateway scans, tool calls, and LLM calls). Distinct from trace_id, which "
    "identifies a single scan. Matches LangSmith / OpenAI Assistants run_id "
    "semantics. Opaque string, max 200 chars, [A-Za-z0-9_.:-] only."
)


class AIRequestSchema(BaseModel):
    input:          str                       = Field(..., min_length=1)
    detection_mode: DetectionMode             = DetectionMode.FAST
    execution_mode: ExecutionMode             = ExecutionMode.SCAN_ONLY
    model:          str | None                = None
    session_id:     str | None                = Field(
        default        = None,
        max_length     = 200,
        pattern        = _SESSION_ID_PATTERN,
        description    = _SESSION_ID_DESC,
    )
    turn_index:     int | None                = Field(
        default     = None,
        ge          = 0,
        le          = 10000,
        description = "Zero-based index of this turn within session_id.",
    )
    run_id:         str | None                = Field(
        default        = None,
        max_length     = 200,
        pattern        = _SESSION_ID_PATTERN,
        description    = _RUN_ID_DESC,
    )
    metadata:       RequestMetadataSchema     = Field(default_factory=RequestMetadataSchema)
    context:        RequestContextSchema      = Field(default_factory=RequestContextSchema)
    options:        RequestOptionsSchema      = Field(default_factory=RequestOptionsSchema)

    @model_validator(mode="after")
    def validate_mode_combinations(self) -> "AIRequestSchema":
        settings = get_settings()

        # Input size limit - driven by MAX_INPUT_CHARS setting (default 8000)
        if len(self.input) > settings.max_input_chars:
            raise ValueError(
                f"Input exceeds maximum length of {settings.max_input_chars} characters "
                f"(received {len(self.input)} characters)."
            )

        # Heuristic token limit - safe for all languages including CJK
        # Conservative estimate: 1 token ≈ 2 chars
        # English: actual ~4 chars/token -> estimate is 2x conservative (safe)
        # CJK:     actual ~1 char/token  -> estimate is 2x conservative (safe)
        # This ensures we never undercount tokens regardless of language
        # Full per-model tiktoken counting is planned (replaces this heuristic)
        token_limit      = settings.max_input_chars // 2
        estimated_tokens = math.ceil(len(self.input) / 2)
        if estimated_tokens > token_limit:
            raise ValueError(
                f"Input exceeds estimated token limit of {token_limit} "
                f"(estimated {estimated_tokens} tokens from {len(self.input)} characters). "
                f"Maximum input is {settings.max_input_chars} characters."
            )

        # stream only valid in proxy mode
        if self.options.stream and self.execution_mode == ExecutionMode.SCAN_ONLY:
            raise StreamNotSupportedError()

        # model required in proxy mode
        if self.execution_mode == ExecutionMode.PROXY and not self.model:
            raise ModelRequiredError()

        # model field ignored in scan_only mode - clear it
        if self.execution_mode == ExecutionMode.SCAN_ONLY:
            self.model = None

        return self

    model_config = {"use_enum_values": True, "populate_by_name": True}