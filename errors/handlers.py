# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from errors.exceptions import WrapSecError

logger = logging.getLogger("wrapsec.errors")


def wrapsec_exception_handler(request: Request, exc: WrapSecError) -> JSONResponse:
    trace_id = str(exc.trace_id) if exc.trace_id else getattr(request.state, "trace_id", "")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code":     exc.code,
                "message":  exc.message,
                "trace_id": trace_id,
            }
        },
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Extract first error message
    errors = exc.errors()
    message = errors[0]["msg"].replace("Value error, ", "") if errors else "Validation error"
    trace_id = getattr(request.state, "trace_id", "")
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code":     "VALIDATION_ERROR",
                "message":  message,
                "trace_id": trace_id,
            }
        },
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
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code":     "INTERNAL_ERROR",
                "message":  "An unexpected error occurred.",
                "trace_id": trace_id,
            }
        },
    )