# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
from cache import keyspace

from cache.redis_client import get_redis
from config.settings import get_settings

logger = logging.getLogger("wrapsec.auth")

# ── Redis key scheme ───────────────────────────────────────────────────────────
#
# auth:failed:{normalized_email}  - INCR failure counter
# auth:locked:{normalized_email}  - lock flag (exists = locked)
#
# Both keys use normalized (lowercase, stripped) email.
# Prevents case-bypass: USER@x.com and user@x.com share the same counter.
#
# TTL behavior:
#   Failure counter key:
#       TTL set on FIRST failure only (fixed window).
#       NOT reset on subsequent failures - window expires naturally.
#       After TTL expires: key deleted by Redis -> fresh window starts.
#
#   Lock key:
#       Uses SETEX on every failure >= MAX_ATTEMPTS.
#       SETEX always overwrites - each failure DURING lockout extends the
#       lockout duration. Attacker who keeps trying extends their own lockout.
#       This is intentional and desirable.
# ──────────────────────────────────────────────────────────────────────────────


def _failed_key(email: str) -> str:
    return keyspace.auth_failed(email)


def _locked_key(email: str) -> str:
    return keyspace.auth_locked(email)


async def is_locked(email: str) -> bool:
    """
    Returns True if the account is currently locked.
    Fast path - checks Redis only, no DB query.
    Call this FIRST in login() before any DB access.
    """
    redis = get_redis()
    return await redis.exists(_locked_key(email)) > 0


async def record_failure(email: str) -> tuple[int, bool]:
    """
    Records one failed login attempt for the given normalized email.
    Returns (attempt_count, is_now_locked).

    INCR and EXPIRE run in a single MULTI/EXEC pipeline so a crash between
    them cannot leave the counter without a TTL (permanent lockout).
    TTL is refreshed on every failure (sliding window), which is intentional:
    an attacker who keeps retrying cannot outlast the counter window.
    Lock key TTL is reset on every failure >= MAX (extends lockout on retry).
    """
    _settings    = get_settings()
    redis        = get_redis()
    failed_key   = _failed_key(email)
    locked_key   = _locked_key(email)
    max_attempts = _settings.auth_max_failed_attempts
    ttl          = _settings.auth_lockout_duration_seconds

    async with redis.pipeline(transaction=True) as pipe:
        pipe.incr(failed_key)
        pipe.expire(failed_key, ttl)
        results = await pipe.execute()
    count = results[0]

    is_now_locked = False
    if count >= max_attempts:
        # SETEX overwrites existing key - extends lockout on each retry
        await redis.setex(locked_key, ttl, "1")
        is_now_locked = True

    return count, is_now_locked


async def clear_failures(email: str) -> None:
    """
    Clears failure counter and lock flag on successful login.
    Call immediately after successful credential verification.
    """
    redis = get_redis()
    await redis.delete(_failed_key(email))
    await redis.delete(_locked_key(email))


async def get_lockout_remaining(email: str) -> int:
    """
    Returns seconds remaining in lockout period.
    Returns 0 if not locked.
    Used to populate retry_after in 429 response.
    """
    redis = get_redis()
    ttl   = await redis.ttl(_locked_key(email))
    return max(0, ttl)
