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
#       TTL refreshed on EVERY failure (sliding window) - see record_failure.
#       Each failure extends the window; it expires only after a full
#       lockout_duration of inactivity, after which Redis deletes the key and a
#       fresh window starts.
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


async def unlock(email: str) -> bool:
    """Clear a lockout on an operator's instruction. Returns True if one existed.

    The lockout itself is deliberately unchanged: the counter's sliding window
    and the lock's extension on every further failure ARE the brute-force
    protection, and relaxing either to make accounts recoverable would trade a
    real control for a convenience.

    What was missing is a way back. `is_locked` is checked before credentials
    are verified, so a locked account refuses the CORRECT password; and
    `clear_failures` runs only after a successful login, which that check makes
    unreachable. An attacker submitting one wrong password per window therefore
    held an account shut indefinitely, and the only remedy was editing the store
    by hand.

    Clears BOTH keys. Removing the lock while leaving the counter at or above
    the threshold would re-lock the account on the next single failure, which
    would look like the unlock had not worked.
    """
    redis   = get_redis()
    existed = await redis.exists(_locked_key(email)) > 0
    await redis.delete(_failed_key(email))
    await redis.delete(_locked_key(email))
    return existed


async def get_lockout_remaining(email: str) -> int:
    """
    Returns seconds remaining in lockout period.
    Returns 0 if not locked.
    Used to populate retry_after in 429 response.
    """
    redis = get_redis()
    ttl   = await redis.ttl(_locked_key(email))
    return max(0, ttl)
