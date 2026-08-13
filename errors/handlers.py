# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
FastAPI exception handlers -- the single place the error envelope is built.

Envelope (LOCKED contract, see docs/internal/i18n_localization_plan.md):

    {"error": {
        "code":     "<stable public ErrorCode>",
        "severity": "ERROR | WARNING | INFO",
        "key":      "<localization key, e.g. errors.CONFLICT>",
        "params":   { ... named ICU args ... },
        "message":  "<English convenience; localized clients resolve key+params>",
        "trace_id": "<correlation id>",
        "invalid_params": [ ... 422 field errors only ... ]
    }}

The response `message` is the safe, generic-where-required English string. The
DETAILED debug_message is logged and NEVER serialized -- the user/debug split
enforces the no-leak / no-enumeration invariant structurally.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from errors.catalog import (
    PYDANTIC_TYPE_TO_VALIDATION,
    VALIDATION_CATALOG,
    ErrorCode,
    ValidationCode,
)
from errors.exceptions import WrapSecError
from errors.response import error_response

logger = logging.getLogger("wrapsec.errors")


def wrapsec_exception_handler(request: Request, exc: WrapSecError) -> JSONResponse:
    trace_id = str(exc.trace_id) if exc.trace_id else getattr(request.state, "trace_id", "")

    # Detail is for the logs only -- never the response.
    if exc.debug_message:
        logger.warning(
            "%s on %s %s trace_id=%s: %s",
            exc.code.value, request.method, request.url.path, trace_id, exc.debug_message,
        )

    # The user-facing message is resolved from the catalog (message=None), never
    # from the exception -- call sites cannot inject user-facing text.
    return error_response(
        exc.code,
        trace_id=trace_id,
        params=exc.params,
        invalid_params=exc.invalid_params,
        status_code=exc.status_code,
    )


def _machine_field(loc) -> str:
    """Raw field name a form can map to an input, e.g. ('body','contact_email') -> 'contact_email'."""
    parts = [p for p in loc if isinstance(p, str) and p != "body"]
    return parts[-1] if parts else "value"


def _classify(err: dict[str, Any]) -> tuple[ValidationCode, dict[str, Any]]:
    """
    Map one Pydantic error to a stable ValidationCode + STRUCTURED render params.
    Params carry only structured values (limits, allowed set) -- never the field
    label, which the dashboard localizes from the machine field name (rules
    section 17). No hand-built English sentences (section 24).
    """
    etype = err.get("type", "")
    msg   = err.get("msg", "")
    ctx   = err.get("ctx", {}) or {}

    if etype == "value_error" and "valid email address" in msg:
        code = ValidationCode.INVALID_EMAIL
    else:
        code = PYDANTIC_TYPE_TO_VALIDATION.get(etype, ValidationCode.INVALID_VALUE)

    params: dict[str, Any] = {}
    if code is ValidationCode.TOO_LONG and "max_length" in ctx:
        params["max_length"] = ctx["max_length"]
    elif code is ValidationCode.TOO_SHORT and "min_length" in ctx:
        params["min_length"] = ctx["min_length"]
    elif code is ValidationCode.INVALID_ENUM and "expected" in ctx:
        params["allowed"] = ctx["expected"]
    return code, params


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Structured per-field array so a form can attach each error to its input and
    # localize the field label + message itself (rules sections 16, 17, 23).
    invalid_params: list[dict[str, Any]] = []
    for err in exc.errors():
        code, params = _classify(err)
        invalid_params.append({
            "field":  _machine_field(err.get("loc", ())),
            "code":   code.value,
            "key":    VALIDATION_CATALOG[code],
            "params": params,
        })

    # Top-level message stays the generic catalog string (message=None); the
    # specifics live in invalid_params. No hand-built English here.
    trace_id = getattr(request.state, "trace_id", "")
    return error_response(
        ErrorCode.VALIDATION_ERROR,
        trace_id=trace_id,
        invalid_params=invalid_params,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", "")
    # Log the full traceback server-side. The client only ever sees the generic
    # message + trace_id (no internal detail leaks), but an unhandled 500 must
    # never be invisible in the logs -- correlate on trace_id.
    logger.error(
        "Unhandled exception on %s %s trace_id=%s: %s",
        request.method, request.url.path, trace_id, exc,
        exc_info=exc,
    )
    return error_response(
        ErrorCode.INTERNAL_ERROR,
        trace_id=trace_id,
        message="An unexpected error occurred.",
    )
