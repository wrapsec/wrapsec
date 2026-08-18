# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
from contextvars import ContextVar

# Context variable - trace ID flows through async context
_trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")


def set_trace_id(trace_id: str) -> None:
    _trace_id_var.set(trace_id)


def get_trace_id() -> str:
    return _trace_id_var.get()


class TraceLogAdapter(logging.LoggerAdapter):
    """
    Logger adapter that automatically injects trace_id
    into every log record.
    """

    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {})
        kwargs["extra"]["trace_id"] = get_trace_id()
        return msg, kwargs


def get_traced_logger(name: str) -> TraceLogAdapter:
    return TraceLogAdapter(logging.getLogger(name), {})