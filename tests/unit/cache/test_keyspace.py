# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Byte-identical contract for cache.keyspace.

These keys address live Redis data. A changed string silently orphans existing
entries (a cache miss at best, a broken lock at worst), so the exact format is
pinned here -- any change is a deliberate, reviewed act.
"""

import uuid

from cache import keyspace


def test_auth_user():
    assert keyspace.auth_user("abc") == "auth:user:abc"


def test_auth_user_uuid_matches_str_form():
    # The middleware passes str(user_id); the service passes the raw value.
    # Both must land on the same key.
    u = uuid.UUID("12345678-1234-5678-1234-567812345678")
    assert keyspace.auth_user(u) == keyspace.auth_user(str(u))


def test_auth_failed_and_locked():
    assert keyspace.auth_failed("a@b.com") == "auth:failed:a@b.com"
    assert keyspace.auth_locked("a@b.com") == "auth:locked:a@b.com"


def test_rate_limit():
    assert keyspace.rate_limit("1.2.3.4") == "rate_limit:1.2.3.4"


def test_endpoint_rate_limit():
    assert keyspace.endpoint_rate_limit("/v1/ai/request", "key_x") \
        == "endpoint:/v1/ai/request:key_x"


def test_login_rate_limit():
    assert keyspace.login_rate_limit("9.9.9.9") == "login:ip:9.9.9.9"
    assert keyspace.login_rate_limit("unknown") == "login:ip:unknown"


def test_idempotency_keys():
    assert keyspace.idempotency_hash("h1") == "idempotency:h1:hash"
    assert keyspace.idempotency_response("h1") == "idempotency:h1:resp"
