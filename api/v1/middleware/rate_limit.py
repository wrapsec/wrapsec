# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
import json

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from config.settings import get_settings
from errors.catalog import ErrorCode
from errors.response import error_response

PUBLIC_PATHS = {"/health", "/health/ready", "/health/live", "/metrics"}

# Only these path prefixes are rate limited -- gateway processing endpoints.
# Dashboard reads, settings, and auth endpoints are excluded.
# /v1/ai/*             covers scan-only requests (/v1/ai/request).
# /v1/chat/completions covers the OpenAI-compatible proxy path.
RATE_LIMITED_PREFIXES = ("/v1/ai", "/v1/chat/completions")


async def _get_live_rate_limit() -> int:
    """
    Resolve the effective rate limit for live keys.
    Priority: Redis cache -> DB settings -> .env default.
    Cache TTL: 60 seconds - changes take effect immediately when updated via
    PUT /v1/settings/rate_limit (which deletes the cache key), or within 1 minute
    for any node that hasn't yet received the invalidation.
    In test mode - always returns .env default to avoid DB/Redis dependency.
    """
    import os
    _settings = get_settings()

    # Skip cache/DB in test mode - avoids Redis/DB dependency in tests
    if os.getenv("TESTING") == "true":
        return _settings.rate_limit_per_minute

    try:
        from cache.redis_client import get_redis
        redis     = get_redis()
        cache_key = "wrapsec:settings:rate_limit"
        cached    = await redis.get(cache_key)
        if cached:
            return int(json.loads(cached).get("per_minute", _settings.rate_limit_per_minute))

        # Cache miss - read from DB
        from db.repositories.settings import SettingsRepository
        from db.session import AsyncSessionFactory
        async with AsyncSessionFactory() as session:
            repo   = SettingsRepository(session)
            stored = await repo.get("rate_limit")
            if stored and "per_minute" in stored:
                limit = int(stored["per_minute"])
                await redis.setex(cache_key, 60, json.dumps(stored))
                return limit
    except Exception:
        pass  # Fail open - use .env default

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

        if not request.url.path.startswith(RATE_LIMITED_PREFIXES):
            return await call_next(request)

        if not get_settings().rate_limit_enabled:
            return await call_next(request)

        # Rate limit per API key - more precise than per IP
        # Falls back to IP if no key (e.g. unauthenticated requests)
        api_key = request.headers.get("x-api-key", "")
        key_id  = getattr(request.state, "key_id", None)

        # get_client_ip trusts x-forwarded-for only when the peer IP is in
        # TRUSTED_PROXY_IPS. Behind nginx, the peer is 127.0.0.1 and all
        # requests would otherwise rate-limit under a single ip:127.0.0.1
        # bucket, letting one loud tenant DoS every other tenant on the box.
        from api.v1.middleware.auth import get_client_ip
        client_ip = get_client_ip(request)

        # Use key_id if available, else hash of api_key, else IP
        if key_id:
            rate_limit_id = f"key:{key_id}"
        elif api_key:
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
            # Record rate limit hit metric - no key_type label since auth hasn't run yet
            try:
                from observability.metrics import record_rate_limit
                record_rate_limit()
            except Exception:
                pass

            response = error_response(
                ErrorCode.RATE_LIMIT_EXCEEDED,
                trace_id=trace_id,
                params={"retry_after": 60},
            )
        else:
            response = await call_next(request)

        response.headers["X-RateLimit-Limit"]     = str(effective_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"]     = str(reset_at)

        return response