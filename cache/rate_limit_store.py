import logging
from cache.redis_client import get_redis
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.cache")
settings = get_settings()

WINDOW_SECS = 60


async def is_rate_limited(client_ip: str, limit: int | None = None) -> tuple[bool, int, int]:
    """
    Sliding window rate limit using Redis.
    Returns (is_limited, remaining, reset_at).

    limit: override the default rate limit per minute.
           Used for trial keys which have a stricter limit.
           Defaults to settings.rate_limit_per_minute.
    """
    try:
        import time
        redis     = get_redis()
        key       = f"rate_limit:{client_ip}"
        now       = time.time()
        window    = WINDOW_SECS
        limit     = limit if limit is not None else settings.rate_limit_per_minute
        reset_at  = int(now + window)

        # Remove old entries outside the window
        await redis.zremrangebyscore(key, 0, now - window)

        # Count current requests in window
        current = await redis.zcard(key)

        if current >= limit:
            return True, 0, reset_at

        # Add current request
        await redis.zadd(key, {str(now): now})
        await redis.expire(key, window)

        remaining = max(0, limit - current - 1)
        return False, remaining, reset_at

    except Exception as e:
        logger.warning(f"Redis rate limit check failed: {e} — allowing request")
        # Fail open — if Redis is down, allow the request
        return False, settings.rate_limit_per_minute, 0


async def get_rate_limit_headers(client_ip: str) -> dict[str, str]:
    """
    Returns rate limit header values without consuming a request slot.
    Used for responses that don't go through the main rate limit check.
    """
    try:
        import time
        redis   = get_redis()
        key     = f"rate_limit:{client_ip}"
        now     = time.time()
        window  = WINDOW_SECS
        limit   = settings.rate_limit_per_minute

        await redis.zremrangebyscore(key, 0, now - window)
        current   = await redis.zcard(key)
        remaining = max(0, limit - current)
        reset_at  = int(now + window)

        return {
            "X-RateLimit-Limit":     str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset":     str(reset_at),
        }
    except Exception:
        return {
            "X-RateLimit-Limit":     str(settings.rate_limit_per_minute),
            "X-RateLimit-Remaining": str(settings.rate_limit_per_minute),
            "X-RateLimit-Reset":     "0",
        }