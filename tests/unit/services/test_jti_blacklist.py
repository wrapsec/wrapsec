# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
M1 regression: JWT jti blacklist.

Pre-M1, /logout revoked the refresh token but left the presented access token
valid until its natural exp (up to 30 min). A stolen access token grabbed
just before the user hit "log out" kept working for the rest of that window.

M1 fixes this by tagging every access token with an opaque `jti` and putting
that jti in a short-lived Redis blacklist on /logout. The auth middleware
rejects any decoded token whose jti is present in the blacklist.

These tests lock in three invariants:

  1. create_access_token embeds a unique jti (per-call, unpredictable).
  2. decode_access_token surfaces jti in the returned payload and requires
     it - a token without jti fails validation.
  3. blacklist_jti + is_blacklisted round-trip: after blacklisting, the same
     jti reads back as True; unrelated jtis stay False.
"""


import pytest

from services.auth import jti_blacklist
from services.auth.token import create_access_token, decode_access_token

# ── create_access_token embeds jti ────────────────────────────────────────────

class _FakeUser:
    """Minimal stand-in for the UserModel columns create_access_token reads."""
    def __init__(self):
        import uuid
        self.id            = uuid.uuid4()
        self.tenant_id     = uuid.uuid4()
        self.dept_id       = None
        self.role          = "ADMIN"
        self.token_version = 1


def test_create_access_token_embeds_unique_jti():
    user = _FakeUser()

    token_a = create_access_token(user)
    token_b = create_access_token(user)

    payload_a = decode_access_token(token_a)
    payload_b = decode_access_token(token_b)

    assert payload_a.get("jti")
    assert payload_b.get("jti")
    # jti must be per-token, not per-user - otherwise blacklisting one
    # revokes every token the user has ever received.
    assert payload_a["jti"] != payload_b["jti"]


def test_decode_rejects_token_without_jti():
    """
    A token stripped of jti (e.g. an old token issued pre-M1 or a forged
    payload) must not authenticate. If jti were optional, the blacklist
    check would silently pass for every legacy token.
    """
    from datetime import datetime, timedelta, timezone

    import jwt as _jwt

    from config.settings import get_settings
    from services.auth.token import ACCESS_TOKEN_AUDIENCE

    _settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub":       "00000000-0000-0000-0000-000000000000",
        "type":      "access",
        "ver":       1,
        "role":      "ADMIN",
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "dept_id":   None,
        "aud":       ACCESS_TOKEN_AUDIENCE,
        "iat":       now,
        "exp":       now + timedelta(minutes=5),
        # deliberately no jti
    }
    token = _jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_algorithm)

    with pytest.raises(Exception):
        decode_access_token(token)


# ── blacklist round-trip ──────────────────────────────────────────────────────

class _FakeRedis:
    """
    Minimal Redis stub: setex writes to a dict, exists checks it. Good enough
    for the blacklist round-trip - we are not testing Redis itself, only that
    the helpers use the right key.
    """
    def __init__(self):
        self.store = {}

    async def setex(self, key, ttl, value):
        self.store[key] = (ttl, value)

    async def exists(self, key):
        return 1 if key in self.store else 0


@pytest.mark.asyncio
async def test_blacklist_and_is_blacklisted_roundtrip(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("cache.redis_client.get_redis", lambda: fake)

    await jti_blacklist.blacklist_jti("token-abc", ttl_seconds=60)

    assert await jti_blacklist.is_blacklisted("token-abc") is True
    # Unrelated jti must not be flagged - otherwise every request would 401.
    assert await jti_blacklist.is_blacklisted("token-xyz") is False


@pytest.mark.asyncio
async def test_blacklist_skips_when_already_expired(monkeypatch):
    """
    TTL <= 0 means the token has already passed its exp - the middleware
    would reject it as expired regardless, so we should not waste a Redis
    write. Guards against callers passing a negative delta.
    """
    fake = _FakeRedis()
    monkeypatch.setattr("cache.redis_client.get_redis", lambda: fake)

    await jti_blacklist.blacklist_jti("token-abc", ttl_seconds=0)
    await jti_blacklist.blacklist_jti("token-abc", ttl_seconds=-5)

    assert fake.store == {}


@pytest.mark.asyncio
async def test_is_blacklisted_fail_open_when_redis_down(monkeypatch):
    """
    Deliberate trade-off documented in jti_blacklist.py: if Redis is
    unavailable, every request would 401 if we failed closed. Fail-open
    keeps the dashboard usable; the natural exp and token_version check
    still bound the risk. Lock in the fail-open contract here so a future
    change to raise on Redis error is caught in review.
    """
    def _boom():
        raise RuntimeError("redis unreachable")

    monkeypatch.setattr("cache.redis_client.get_redis", _boom)

    assert await jti_blacklist.is_blacklisted("token-abc") is False
