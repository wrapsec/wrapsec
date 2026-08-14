# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
import logging
import secrets
from datetime import timedelta
from typing import TYPE_CHECKING

import jwt
from jwt.exceptions import InvalidTokenError

from config.settings import get_settings
from services.time import utc_now

if TYPE_CHECKING:
    from db.models import MembershipModel, UserModel

logger = logging.getLogger("wrapsec.auth")

ACCESS_TOKEN_AUDIENCE = "wrapsec-dashboard"
# Audience claim prevents tokens issued for the dashboard from being reused
# against other services even if they share the same secret_key.
# Must match exactly on token creation and validation.


def create_access_token(
    user: "UserModel", membership: "MembershipModel | None" = None
) -> str:
    """
    Creates a short-lived JWT access token scoped to one membership.

    Identity model D2 Option B: the authz claims (tenant_id, role, dept_id) come
    from the MEMBERSHIP the session is scoped to; identity claims (sub, ver) come
    from the user. When `membership` is omitted the claims fall back to the user
    row -- a transitional path for callers (and tests) not yet membership-aware,
    valid only while users.tenant_id/role/dept_id still mirror the membership.

    Claims and their purposes:
        sub        - user UUID string (JWT subject - standard claim)
        jti        - opaque token id: enables per-token revocation via Redis blacklist
        type       - "access": rejects refresh tokens used as access tokens
        ver        - user.token_version: detects session invalidation
        role       - membership role: used by RBAC dependencies (require_role)
        tenant_id  - security boundary: the membership's tenant; the middleware
                     confirms the user still holds a membership in it
        dept_id    - isolation boundary: None for ADMIN, str UUID for others
        aud        - ACCESS_TOKEN_AUDIENCE: cross-service token reuse prevention
        iat        - issued-at (standard JWT)
        exp        - expiry (standard JWT)

    Deliberately excluded:
        email       - unnecessary exposure if token is logged
        permissions - not enforced in v1 (roles only)
    """
    _settings = get_settings()
    now     = utc_now()
    expires = now + timedelta(minutes=_settings.jwt_access_token_expire_minutes)

    src = membership if membership is not None else user
    payload = {
        "sub":       str(user.id),
        "jti":       secrets.token_urlsafe(16),
        "type":      "access",
        "ver":       user.token_version,
        "role":      src.role,
        "tenant_id": str(src.tenant_id),
        "dept_id":   str(src.dept_id) if src.dept_id else None,
        "aud":       ACCESS_TOKEN_AUDIENCE,
        "iat":       now,
        "exp":       expires,
    }
    return jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_algorithm)


def create_refresh_token() -> tuple[str, str]:
    """
    Creates an opaque refresh token pair.
    Returns: (raw_token, token_hash)

    raw_token  - 32 random bytes, URL-safe base64
                 Sent to client ONCE via httpOnly cookie.
                 NEVER stored server-side (not in DB, not in Redis, not in logs).

    token_hash - SHA-256(raw_token.encode())
                 Stored in refresh_tokens.token_hash.
                 Raw token cannot be reconstructed from hash.

    Security: DB compromise cannot yield raw refresh tokens.
    """
    raw    = secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def decode_access_token(token: str) -> dict:
    """
    Decodes and validates a JWT access token.

    Validates in order:
        1. Signature  - HMAC-SHA256 with secret_key
        2. Expiry     - exp claim not in the past
        3. Audience   - aud == ACCESS_TOKEN_AUDIENCE
        4. Type       - type == "access" (rejects refresh tokens used as access)
        5. Required   - sub, tenant_id, role, ver all present and non-null

    Error handling (R4 fix):
        Full error detail logged internally at WARNING level.
        Generic message raised to caller - caller MUST NOT pass details to client.
        Prevents token oracle attacks where error message reveals validation state.

    Raises: InvalidTokenError with generic message on any failure.
    Returns: validated payload dict on success.
    """
    _settings = get_settings()

    # Defense-in-depth: reject alg mismatches before decode. jwt.decode already
    # constrains algorithms via the allowlist, but pre-checking the unverified
    # header adds a second gate against algorithm-confusion attacks (alg=none,
    # HS/RS confusion) if a future PyJWT bug ever weakens that check.
    try:
        header_alg = jwt.get_unverified_header(token).get("alg")
    except InvalidTokenError as e:
        logger.warning("auth token_decode_failed reason=%s", str(e))
        raise InvalidTokenError("Token validation failed") from None

    if header_alg != _settings.jwt_algorithm:
        logger.warning(
            "auth token_decode_failed reason=alg_mismatch got=%s expected=%s",
            header_alg, _settings.jwt_algorithm,
        )
        raise InvalidTokenError("Token validation failed")

    try:
        payload = jwt.decode(
            token,
            _settings.secret_key,
            algorithms = [_settings.jwt_algorithm],
            audience   = ACCESS_TOKEN_AUDIENCE,
        )
    except InvalidTokenError as e:
        logger.warning("auth token_decode_failed reason=%s", str(e))
        raise InvalidTokenError("Token validation failed") from None  # generic - no details to client

    if payload.get("type") != "access":
        logger.warning(
            "auth token_decode_failed reason=wrong_type type=%s",
            payload.get("type"),
        )
        raise InvalidTokenError("Token validation failed")  # generic

    required = ["sub", "tenant_id", "role", "ver", "jti"]
    missing  = [f for f in required if payload.get(f) is None]
    if missing:
        logger.warning(
            "auth token_decode_failed reason=missing_fields fields=%s", missing
        )
        raise InvalidTokenError("Token validation failed")  # generic

    return payload


def hash_refresh_token(raw_token: str) -> str:
    """
    Returns SHA-256 hash of a raw refresh token.
    Used for DB lookup in refresh() and logout() flows.
    NEVER log the raw_token argument.
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()
