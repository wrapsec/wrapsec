import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from config.settings import get_settings

settings = get_settings()

PUBLIC_PATHS = {"/health", "/health/ready", "/health/live", "/metrics"}


async def _get_live_rate_limit() -> int:
    """
    Resolve the effective rate limit for live keys.
    Priority: Redis cache → DB settings → .env default.
    Cache TTL: 5 minutes — changes take effect within 5 minutes.
    In test mode — always returns .env default to avoid DB/Redis dependency.
    """
    import os
    _settings = get_settings()

    # Skip cache/DB in test mode — avoids Redis/DB dependency in tests
    if os.getenv("TESTING") == "true":
        return _settings.rate_limit_per_minute

    try:
        from cache.redis_client import get_redis
        redis     = get_redis()
        cache_key = "wrapsec:settings:rate_limit"
        cached    = await redis.get(cache_key)
        if cached:
            import json
            return int(json.loads(cached).get("per_minute", _settings.rate_limit_per_minute))

        # Cache miss — read from DB
        from db.session import AsyncSessionFactory
        from db.repositories.settings import SettingsRepository
        async with AsyncSessionFactory() as session:
            repo   = SettingsRepository(session)
            stored = await repo.get("rate_limit")
            if stored and "per_minute" in stored:
                limit = int(stored["per_minute"])
                # Cache for 5 minutes
                import json
                await redis.setex(cache_key, 300, json.dumps(stored))
                return limit
    except Exception:
        pass  # Fail open — use .env default

    return _settings.rate_limit_per_minute


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
        effective_limit = await _get_live_rate_limit()
        is_limited, remaining, reset_at = await is_rate_limited(
            rate_limit_id,
            limit=effective_limit,
        )

        if is_limited:
            # Record rate limit hit metric — no key_type label since auth hasn't run yet
            try:
                from observability.metrics import record_rate_limit
                record_rate_limit()
            except Exception:
                pass

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

        response.headers["X-RateLimit-Limit"]     = str(effective_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"]     = str(reset_at)

        return response