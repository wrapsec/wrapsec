# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The single builder for the error envelope.

Both the registered exception handlers (errors/handlers.py) and the sites that
must return an error directly -- middleware and a few endpoints that cannot
raise into the handler chain -- go through here, so the wire shape is defined in
exactly one place:

    {"error": {code, severity, key, params, message, trace_id, invalid_params?}}

See the LOCKED contract in docs/internal/i18n_localization_plan.md.
"""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse

from errors.catalog import ErrorCode, ERROR_CATALOG
from errors.messages import get_message


def build_error_envelope(
    *,
    code:     str,
    severity: str,
    key:      str,
    message:  str,
    trace_id: str,
    params:   dict[str, Any] | None = None,
    invalid_params: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {
        "code":     code,
        "severity": severity,
        "key":      key,
        "params":   params or {},
        "message":  message,
        "trace_id": trace_id,
    }
    if invalid_params:
        error["invalid_params"] = invalid_params
    return {"error": error}


def error_response(
    code: ErrorCode,
    *,
    trace_id: str = "",
    message:  str | None = None,
    params:   dict[str, Any] | None = None,
    invalid_params: list[dict[str, Any]] | None = None,
    status_code: int | None = None,
) -> JSONResponse:
    """
    Build a catalog-driven error JSONResponse. `message` defaults to the
    generated English for the code's key; pass it explicitly to keep a
    site-specific English string (localized clients resolve key+params anyway).
    """
    meta = ERROR_CATALOG[code]
    msg  = message if message is not None else (get_message(meta.localization_key, params) or code.value)
    return JSONResponse(
        status_code=status_code if status_code is not None else meta.status_code,
        content=build_error_envelope(
            code=code.value,
            severity=meta.severity.value,
            key=meta.localization_key,
            message=msg,
            trace_id=trace_id,
            params=params,
            invalid_params=invalid_params,
        ),
    )
