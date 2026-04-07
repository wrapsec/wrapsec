import uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from observability.tracing import set_trace_id


class TraceMiddleware(BaseHTTPMiddleware):
    """
    Injects a trace ID into every request.
    Uses X-Trace-Id header if provided by client,
    otherwise generates a new one.
    Propagates trace ID in response headers.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        trace_id = (
            request.headers.get("x-trace-id")
            or f"req_{uuid.uuid4().hex[:8]}"
        )

        # Attach to request state — available in all endpoints
        request.state.trace_id = trace_id
        set_trace_id(trace_id)

        response = await call_next(request)

        # Propagate in response headers
        response.headers["X-Trace-Id"] = trace_id

        return response