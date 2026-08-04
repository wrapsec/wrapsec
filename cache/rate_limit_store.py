# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
from cache import keyspace
import time
import uuid as _uuid

from cache.redis_client import get_redis
from config.settings import get_settings

logger = logging.getLogger("wrapsec.cache")

WINDOW_SECS = 60

# Atomic sliding-window rate limit via Lua.
# ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE as separate commands allow two
# concurrent requests to both pass the limit check if they race at the boundary.
# Lua scripts execute atomically in Redis - no race condition possible.
_RATE_LIMIT_LUA = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[4]
local cost   = tonumber(ARGV[5])

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = tonumber(redis.call('ZCARD', key))

if count + cost > limit then
    local left = limit - count
    if left < 0 then left = 0 end
    return {1, left}
end

for i = 1, cost do
    redis.call('ZADD', key, now, member .. ':' .. i)
end
redis.call('EXPIRE', key, window)
return {0, limit - count - cost}
"""


async def is_rate_limited(
    client_ip: str,
    limit: int | None = None,
    cost: int = 1,
) -> tuple[bool, int, int]:
    """
    Sliding window rate limit using Redis.
    Returns (is_limited, remaining, reset_at).

    limit: override the default rate limit per minute.
           Used for trial keys which have a stricter limit.
           Defaults to settings.rate_limit_per_minute.
    cost:  number of slots this call consumes (weighted rate limiting).
           Defaults to 1. A batch of N items charges cost=N so it cannot
           amplify a caller's budget past the per-minute limit. The check is
           all-or-nothing: if the full cost does not fit, nothing is consumed
           and is_limited is True.

    Availability trade-off: fails OPEN when Redis is unavailable.
    Rate limiting is silently disabled during Redis outages to preserve
    API availability. Monitor Redis health and alert on connection errors
    if strict enforcement during outages is required.
    """
    try:
        redis    = get_redis()
        key      = keyspace.rate_limit(client_ip)
        now      = time.time()
        eff_lim  = limit if limit is not None else get_settings().rate_limit_per_minute
        reset_at = int(now + WINDOW_SECS)
        cost     = max(1, int(cost))

        # Unique member prefix prevents duplicate scores from colliding in the
        # sorted set; the Lua script appends :1..:cost for weighted consumption.
        member = f"{now}:{_uuid.uuid4().hex}"
        result = await redis.eval(
            _RATE_LIMIT_LUA, 1, key,
            str(now), str(WINDOW_SECS), str(eff_lim), member, str(cost),
        )
        is_limited = bool(result[0])
        remaining  = int(result[1])
        return is_limited, remaining, reset_at

    except Exception as e:
        logger.warning("Redis rate limit check failed: %s - allowing request", e)
        # Fail open - if Redis is down, allow the request
        return False, get_settings().rate_limit_per_minute, 0


async def get_rate_limit_headers(client_ip: str) -> dict[str, str]:
    """
    Returns rate limit header values without consuming a request slot.
    Used for responses that don't go through the main rate limit check.
    """
    try:
        redis   = get_redis()
        key     = keyspace.rate_limit(client_ip)
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