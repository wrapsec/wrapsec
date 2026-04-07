import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from config.settings import get_settings

settings = get_settings()

PUBLIC_PATHS = {"/health", "/health/ready", "/health/live", "/metrics"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP sliding window rate limiting using Redis.
    Falls back to allowing requests if Redis is unavailable.
    Adds X-RateLimit-Limit/Remaining/Reset headers to all responses.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        if not settings.rate_limit_enabled:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        trace_id  = getattr(request.state, "trace_id", "")

        from cache.rate_limit_store import is_rate_limited
        is_limited, remaining, reset_at = await is_rate_limited(client_ip)

        if is_limited:
            response = JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code":     "RATE_LIMIT_EXCEEDED",
                        "message":  "Too many requests. Retry after 60 seconds.",
                        "trace_id": trace_id,
                    }
                },
            )
        else:
            response = await call_next(request)

        response.headers["X-RateLimit-Limit"]     = str(settings.rate_limit_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"]     = str(reset_at)

        return response