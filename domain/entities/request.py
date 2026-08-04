# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from dataclasses import dataclass, field
from datetime import datetime, timezone
from domain.enums import DetectionMode, ExecutionMode
from domain.value_objects.trace_id import TraceId


@dataclass
class RequestMetadata:
    tenant_id: str | None = None
    source:    str | None = None
    user_id:   str | None = None


@dataclass
class RequestContext:
    user_role:   str | None = None
    sensitivity: str | None = None  # low | medium | high


@dataclass
class RequestOptions:
    stream: bool = False
    debug:  bool = False


@dataclass
class IncomingRequest:
    input:          str
    trace_id:       TraceId                = field(default_factory=TraceId.generate)
    detection_mode: DetectionMode          = DetectionMode.FAST
    execution_mode: ExecutionMode          = ExecutionMode.SCAN_ONLY
    model:          str | None             = None
    # Trust-boundary provenance of `input` (the InputSource enum value as a plain
    # string, e.g. "user_prompt", "retrieved_document"). Kept as a str so a new
    # source needs no entity change. Carried through so the policy layer can apply
    # source-aware posture; detection never reads it.
    input_source:   str                    = "user_prompt"
    metadata:       RequestMetadata        = field(default_factory=RequestMetadata)
    context:        RequestContext         = field(default_factory=RequestContext)
    options:        RequestOptions         = field(default_factory=RequestOptions)
    received_at:    datetime               = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_proxy_mode(self) -> bool:
        return self.execution_mode == ExecutionMode.PROXY

    def is_full_detection(self) -> bool:
        return self.detection_mode == DetectionMode.FULL

    def requires_streaming(self) -> bool:
        return self.options.stream and self.is_proxy_mode()

    def is_debug(self) -> bool:
        return self.options.debug