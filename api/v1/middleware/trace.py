# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import re
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from observability.tracing import set_trace_id

# Allow only safe alphanumeric-plus-hyphen/underscore trace IDs (max 64 chars)
_TRACE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


class TraceMiddleware(BaseHTTPMiddleware):
    """
    Injects a trace ID into every request.
    Uses X-Trace-Id header if provided by client (validated format),
    otherwise generates a new one.
    Propagates trace ID in response headers.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        client_trace_id = request.headers.get("x-trace-id", "")
        if client_trace_id and _TRACE_ID_RE.match(client_trace_id):
            trace_id = client_trace_id
        else:
            trace_id = f"req_{uuid.uuid4().hex}"

        # Attach to request state - available in all endpoints
        request.state.trace_id = trace_id
        set_trace_id(trace_id)

        response = await call_next(request)

        # Propagate in response headers
        response.headers["X-Trace-Id"] = trace_id

        return response