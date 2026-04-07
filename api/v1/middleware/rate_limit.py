import time
from collections import defaultdict
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from config.settings import get_settings

settings = get_settings()

# In-memory rate limit store — will be replaced by Redis
# Structure: {ip: [timestamp, timestamp, ...]}
_request_log: dict[str, list[float]] = defaultdict(list)

PUBLIC_PATHS = {"/health", "/health/ready", "/health/live"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP sliding window rate limiting.
    Adds X-RateLimit-Limit/Remaining/Reset headers to all responses.
    Returns 429 when limit is exceeded.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        if not settings.rate_limit_enabled:
            return await call_next(request)

        client_ip  = request.client.host if request.client else "unknown"
        now        = time.time()
        window     = 60.0
        limit      = settings.rate_limit_per_minute

        # Sliding window — remove timestamps older than window
        _request_log[client_ip] = [
            t for t in _request_log[client_ip]
            if now - t < window
        ]

        current_count = len(_request_log[client_ip])
        remaining     = max(0, limit - current_count)
        reset_at      = int(now + window)

        if current_count >= limit:
            trace_id = getattr(request.state, "trace_id", "")
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
            _request_log[client_ip].append(now)
            remaining -= 1
            response   = await call_next(request)

        # Always add rate limit headers
        response.headers["X-RateLimit-Limit"]     = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"]     = str(reset_at)

        return response