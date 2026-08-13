# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Single source of truth for dynamic Redis key names.

Every runtime Redis key built from a variable is constructed here, so the
keyspace lives in one place and a prefix change (or a typo) cannot silently
split a namespace -- the classic failure where a writer and a reader drift onto
different keys and a cache or lock quietly stops working. `auth:user` in
particular is built by both the auth middleware and the auth service; a single
builder guarantees they never disagree.

Keys MUST stay byte-identical to what shipped: changing one is a deliberate,
reviewable act (and usually needs a cache flush). tests/unit/cache/test_keyspace
pins the exact strings.

Static singleton keys that are already module-level constants (the retention and
circuit-breaker leases, setup flag, admin-limits cache) are intentionally left
where they are -- they are not the inline-f-string drift surface this module
addresses.
"""

from __future__ import annotations

# --- auth --------------------------------------------------------------

def auth_user(user_id: object) -> str:
    """Cached auth principal, invalidated on logout / role change (TTL 1800s).
    Built by both the auth middleware and the auth service."""
    return f"auth:user:{user_id}"


def auth_failed(email: str) -> str:
    """Failed-login counter for an account (fixed window)."""
    return f"auth:failed:{email}"


def auth_locked(email: str) -> str:
    """Account-lock flag; existence means locked."""
    return f"auth:locked:{email}"


# --- rate limiting -----------------------------------------------------

def rate_limit(client_ip: str) -> str:
    """Global per-IP rate-limit bucket."""
    return f"rate_limit:{client_ip}"


def endpoint_rate_limit(path: str, identity: str) -> str:
    """Per-endpoint, per-identity rate-limit bucket."""
    return f"endpoint:{path}:{identity}"


def login_rate_limit(ip: str) -> str:
    """Stricter per-IP rate-limit bucket for the login route."""
    return f"login:ip:{ip}"


# --- idempotency -------------------------------------------------------

def idempotency_hash(idem_hash: str) -> str:
    """Idempotency claim marker; holds the request body hash."""
    return f"idempotency:{idem_hash}:hash"


def idempotency_response(idem_hash: str) -> str:
    """Cached response body for a completed idempotent request."""
    return f"idempotency:{idem_hash}:resp"
