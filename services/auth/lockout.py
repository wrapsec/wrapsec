import logging

from cache.redis_client import get_redis
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.auth")
settings = get_settings()

# ── Redis key scheme ───────────────────────────────────────────────────────────
#
# auth:failed:{normalized_email}  — INCR failure counter
# auth:locked:{normalized_email}  — lock flag (exists = locked)
#
# Both keys use normalized (lowercase, stripped) email.
# Prevents case-bypass: USER@x.com and user@x.com share the same counter.
#
# TTL behavior:
#   Failure counter key:
#       TTL set on FIRST failure only (fixed window).
#       NOT reset on subsequent failures — window expires naturally.
#       After TTL expires: key deleted by Redis → fresh window starts.
#
#   Lock key:
#       Uses SETEX on every failure >= MAX_ATTEMPTS.
#       SETEX always overwrites — each failure DURING lockout extends the
#       lockout duration. Attacker who keeps trying extends their own lockout.
#       This is intentional and desirable.
# ──────────────────────────────────────────────────────────────────────────────


def _failed_key(email: str) -> str:
    return f"auth:failed:{email}"


def _locked_key(email: str) -> str:
    return f"auth:locked:{email}"


async def is_locked(email: str) -> bool:
    """
    Returns True if the account is currently locked.
    Fast path — checks Redis only, no DB query.
    Call this FIRST in login() before any DB access.
    """
    redis = get_redis()
    return await redis.exists(_locked_key(email)) > 0


async def record_failure(email: str) -> tuple[int, bool]:
    """
    Records one failed login attempt for the given normalized email.
    Returns (attempt_count, is_now_locked).

    Counter TTL is set on first failure only (fixed window).
    Lock key TTL is reset on every failure >= MAX (extends lockout on retry).
    """
    redis        = get_redis()
    failed_key   = _failed_key(email)
    locked_key   = _locked_key(email)
    max_attempts = settings.auth_max_failed_attempts
    ttl          = settings.auth_lockout_duration_seconds

    count = await redis.incr(failed_key)
    if count == 1:
        # Set TTL on first failure only — fixed window
        await redis.expire(failed_key, ttl)

    is_now_locked = False
    if count >= max_attempts:
        # SETEX overwrites existing key — extends lockout on each retry
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
