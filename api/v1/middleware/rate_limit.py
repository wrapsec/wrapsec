import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from config.settings import get_settings

settings = get_settings()

PUBLIC_PATHS = {"/health", "/health/ready", "/health/live", "/metrics"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-API-key sliding window rate limiting using Redis.
    Falls back to per-IP if no key present.
    Falls back to allowing requests if Redis unavailable.
    Adds X-RateLimit-Limit/Remaining/Reset headers to all responses.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        if not settings.rate_limit_enabled:
            return await call_next(request)

        # Rate limit per API key — more precise than per IP
        # Falls back to IP if no key (e.g. unauthenticated requests)
        api_key   = request.headers.get("x-api-key", "")
        key_id    = getattr(request.state, "key_id", None)
        client_ip = request.client.host if request.client else "unknown"

        # Use key_id if available, else hash of api_key, else IP
        if key_id:
            rate_limit_id = f"key:{key_id}"
        elif api_key:
            import hashlib
            rate_limit_id = f"key:{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"
        else:
            rate_limit_id = f"ip:{client_ip}"

        trace_id = getattr(request.state, "trace_id", "")

        from cache.rate_limit_store import is_rate_limited
        is_limited, remaining, reset_at = await is_rate_limited(rate_limit_id)

        if is_limited:
            response = JSONResponse(
                status_code = 429,
                content = {
                    "error": {
                        "code":     "RATE_LIMITED",
                        "message":  "Rate limit exceeded. Retry after 60 seconds.",
                        "trace_id": trace_id,
                    }
                },
            )
        else:
            response = await call_next(request)

        response.headers["X-RateLimit-Limit"]     = str(settings.rate_limit_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"]     = str(reset_at)

        return response