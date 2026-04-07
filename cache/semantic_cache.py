import json
import hashlib
import logging
from cache.redis_client import get_redis
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.cache")
settings = get_settings()

CACHE_PREFIX  = "prompt_cache:"
CACHE_TTL     = 3600  # 1 hour


def _cache_key(text: str, detection_mode: str) -> str:
    """
    Generate a deterministic cache key from prompt + detection mode.
    Same prompt + same mode = same result.
    """
    content = f"{detection_mode}:{text.strip().lower()}"
    digest  = hashlib.sha256(content.encode()).hexdigest()
    return f"{CACHE_PREFIX}{digest}"


async def get_cached_result(text: str, detection_mode: str) -> dict | None:
    """
    Return cached detection result if available.
    Returns None on cache miss or Redis failure.
    """
    try:
        redis  = get_redis()
        key    = _cache_key(text, detection_mode)
        cached = await redis.get(key)

        if cached:
            logger.debug(f"Cache hit for key {key[:20]}...")
            return json.loads(cached)

        return None

    except Exception as e:
        logger.warning(f"Cache get failed: {e}")
        return None


async def set_cached_result(
    text:           str,
    detection_mode: str,
    result:         dict,
    ttl:            int = CACHE_TTL,
) -> None:
    """
    Cache a detection result.
    Only cache ALLOW decisions — BLOCK/SANITIZE should always re-evaluate.
    """
    try:
        # Only cache clean results
        if result.get("decision") != "ALLOW":
            return

        redis = get_redis()
        key   = _cache_key(text, detection_mode)
        await redis.setex(key, ttl, json.dumps(result))
        logger.debug(f"Cached result for key {key[:20]}...")

    except Exception as e:
        logger.warning(f"Cache set failed: {e}")


async def invalidate(text: str, detection_mode: str) -> None:
    try:
        redis = get_redis()
        key   = _cache_key(text, detection_mode)
        await redis.delete(key)
    except Exception as e:
        logger.warning(f"Cache invalidate failed: {e}")