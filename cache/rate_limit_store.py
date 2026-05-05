# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
import time
import uuid as _uuid

from cache.redis_client import get_redis
from config.settings import get_settings

logger = logging.getLogger("wrapsec.cache")

WINDOW_SECS = 60

# Atomic sliding-window rate limit via Lua.
# ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE as separate commands allow two
# concurrent requests to both pass the limit check if they race at the boundary.
# Lua scripts execute atomically in Redis — no race condition possible.
_RATE_LIMIT_LUA = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = tonumber(redis.call('ZCARD', key))

if count >= limit then
    return {1, 0}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, window)
return {0, limit - count - 1}
"""


async def is_rate_limited(client_ip: str, limit: int | None = None) -> tuple[bool, int, int]:
    """
    Sliding window rate limit using Redis.
    Returns (is_limited, remaining, reset_at).

    limit: override the default rate limit per minute.
           Used for trial keys which have a stricter limit.
           Defaults to settings.rate_limit_per_minute.

    Availability trade-off: fails OPEN when Redis is unavailable.
    Rate limiting is silently disabled during Redis outages to preserve
    API availability. Monitor Redis health and alert on connection errors
    if strict enforcement during outages is required.
    """
    try:
        redis    = get_redis()
        key      = f"rate_limit:{client_ip}"
        now      = time.time()
        eff_lim  = limit if limit is not None else get_settings().rate_limit_per_minute
        reset_at = int(now + WINDOW_SECS)

        # Unique member prevents duplicate scores from colliding in the sorted set
        member = f"{now}:{_uuid.uuid4().hex}"
        result = await redis.eval(
            _RATE_LIMIT_LUA, 1, key,
            str(now), str(WINDOW_SECS), str(eff_lim), member,
        )
        is_limited = bool(result[0])
        remaining  = int(result[1])
        return is_limited, remaining, reset_at

    except Exception as e:
        logger.warning("Redis rate limit check failed: %s — allowing request", e)
        # Fail open — if Redis is down, allow the request
        return False, get_settings().rate_limit_per_minute, 0


async def get_rate_limit_headers(client_ip: str) -> dict[str, str]:
    """
    Returns rate limit header values without consuming a request slot.
    Used for responses that don't go through the main rate limit check.
    """
    try:
        redis   = get_redis()
        key     = f"rate_limit:{client_ip}"
        now     = time.time()
        limit   = get_settings().rate_limit_per_minute

        await redis.zremrangebyscore(key, 0, now - WINDOW_SECS)
        current   = await redis.zcard(key)
        remaining = max(0, limit - current)
        reset_at  = int(now + WINDOW_SECS)

        return {
            "X-RateLimit-Limit":     str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset":     str(reset_at),
        }
    except Exception:
        return {
            "X-RateLimit-Limit":     str(get_settings().rate_limit_per_minute),
            "X-RateLimit-Remaining": str(get_settings().rate_limit_per_minute),
            "X-RateLimit-Reset":     "0",
        }