# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import json
import logging
import time
from typing import ClassVar

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger("wrapsec.access")


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Structured JSON request/response logging.
    Logs method, path, status, latency, trace_id.
    Skips /health endpoints to reduce noise.
    """

    SKIP_PATHS: ClassVar[set[str]] = {"/health", "/health/ready", "/health/live", "/metrics"}

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        start      = time.perf_counter()
        trace_id   = getattr(request.state, "trace_id", "")

        response   = await call_next(request)

        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        log_entry = {
            "event":      "request",
            "method":     request.method,
            "path":       request.url.path,
            "status":     response.status_code,
            "latency_ms": latency_ms,
            "trace_id":   trace_id,
            "client_ip":  request.client.host if request.client else "",
        }

        if response.status_code >= 500:
            logger.error(json.dumps(log_entry))
        elif response.status_code >= 400:
            logger.warning(json.dumps(log_entry))
        else:
            logger.info(json.dumps(log_entry))

        return response