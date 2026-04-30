# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import json
import hashlib
import logging
from cache.redis_client import get_redis
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.cache")
settings = get_settings()

CACHE_PREFIX  = "prompt_cache:"
CACHE_TTL     = 3600  # 1 hour


def _cache_key(text: str, detection_mode: str, execution_mode: str = "scan_only") -> str:
    """
    Generate a deterministic cache key from prompt + detection mode + execution mode.
    Same prompt + same modes = same result.
    """
    content = f"{detection_mode}:{execution_mode}:{text.strip().lower()}"
    digest  = hashlib.sha256(content.encode()).hexdigest()
    return f"{CACHE_PREFIX}{digest}"


async def get_cached_result(
    text:           str,
    detection_mode: str,
    execution_mode: str = "scan_only",
) -> dict | None:
    try:
        redis  = get_redis()
        key    = _cache_key(text, detection_mode, execution_mode)
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
    execution_mode: str,
    result:         dict,
    ttl:            int = CACHE_TTL,
) -> None:
    try:
        if result.get("decision") != "ALLOW":
            return
        redis = get_redis()
        key   = _cache_key(text, detection_mode, execution_mode)
        await redis.setex(key, ttl, json.dumps(result))
        logger.debug(f"Cached result for key {key[:20]}...")
    except Exception as e:
        logger.warning(f"Cache set failed: {e}")


async def invalidate(
    text:           str,
    detection_mode: str,
    execution_mode: str = "scan_only",
) -> None:
    try:
        redis = get_redis()
        key   = _cache_key(text, detection_mode, execution_mode)
        await redis.delete(key)
    except Exception as e:
        logger.warning(f"Cache invalidate failed: {e}")