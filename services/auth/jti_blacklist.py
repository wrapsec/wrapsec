# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
M1: per-token JWT revocation via Redis blacklist.

Regular /logout only revokes the refresh token - the outstanding access token
still validates for up to jwt_access_token_expire_minutes (default 30). That
window is a session-hijack primitive: a token stolen right before logout keeps
working until natural expiry.

Bumping token_version on every logout would invalidate all sessions on all
devices, which is what logout_all_sessions is for. The blacklist gives us
per-token revocation without the cross-device blast radius:

  - On logout: put jti in Redis with TTL = remaining lifetime of the token.
  - On auth: middleware rejects tokens whose jti is present in Redis.

Failure mode: Redis unavailable -> is_blacklisted returns False (fail-open).
This is a deliberate trade-off - if Redis is down, treating every token as
revoked would break the whole dashboard. The natural token_version check on
password/role change and eventual exp still bound the risk.
"""

import logging

logger = logging.getLogger("wrapsec.auth")

_KEY_PREFIX = "revoked:jti:"


async def blacklist_jti(jti: str, ttl_seconds: int) -> None:
    """
    Marks a token id as revoked for the given TTL. Called by /logout.

    ttl_seconds should be the token's remaining lifetime (exp - now). Setting
    a longer TTL is harmless (just wastes Redis memory); setting it shorter
    would let a revoked token become valid again before its exp.
    """
    if ttl_seconds <= 0:
        return  # already expired - no need to blacklist

    try:
        from cache.redis_client import get_redis
        await get_redis().setex(_KEY_PREFIX + jti, ttl_seconds, "1")
    except Exception as e:
        # Do not let Redis failure block logout - the refresh token has
        # already been revoked in the DB and token_version is unchanged,
        # so the worst case is the access token remains valid until exp.
        logger.warning("jti_blacklist_write_failed jti_prefix=%s err=%s",
                       jti[:6], e)


async def is_blacklisted(jti: str) -> bool:
    """
    Returns True if the token id has been revoked and Redis is reachable.
    Returns False on Redis failure (fail-open - see module docstring).
    """
    try:
        from cache.redis_client import get_redis
        return await get_redis().exists(_KEY_PREFIX + jti) > 0
    except Exception as e:
        logger.warning("jti_blacklist_read_failed jti_prefix=%s err=%s",
                       jti[:6], e)
        return False
