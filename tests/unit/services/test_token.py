# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import datetime
import uuid
from datetime import timedelta, timezone
from unittest.mock import MagicMock

import pytest
from jwt.exceptions import InvalidTokenError

from services.auth.token import (
    ACCESS_TOKEN_AUDIENCE,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_refresh_token,
)


def _make_user(role="DEVELOPER", dept_id=None):
    user = MagicMock()
    user.id            = uuid.uuid4()
    user.token_version = 1
    user.role          = role
    user.tenant_id     = uuid.uuid4()
    user.dept_id       = dept_id
    return user


# ── create_access_token ────────────────────────────────────────────────────────

def test_access_token_has_sub():
    user    = _make_user()
    payload = decode_access_token(create_access_token(user))
    assert payload["sub"] == str(user.id)


def test_access_token_type_is_access():
    user    = _make_user()
    payload = decode_access_token(create_access_token(user))
    assert payload["type"] == "access"


def test_access_token_has_ver():
    user               = _make_user()
    user.token_version = 3
    payload            = decode_access_token(create_access_token(user))
    assert payload["ver"] == 3


def test_access_token_has_audience():
    user    = _make_user()
    payload = decode_access_token(create_access_token(user))
    assert payload["aud"] == ACCESS_TOKEN_AUDIENCE


def test_access_token_has_tenant_id():
    user    = _make_user()
    payload = decode_access_token(create_access_token(user))
    assert payload["tenant_id"] == str(user.tenant_id)


def test_access_token_has_role():
    user    = _make_user(role="ADMIN")
    payload = decode_access_token(create_access_token(user))
    assert payload["role"] == "ADMIN"


def test_access_token_dept_null_for_admin():
    user    = _make_user(role="ADMIN", dept_id=None)
    payload = decode_access_token(create_access_token(user))
    assert payload["dept_id"] is None


def test_access_token_dept_present_for_developer():
    dept_id = uuid.uuid4()
    user    = _make_user(role="DEVELOPER", dept_id=dept_id)
    payload = decode_access_token(create_access_token(user))
    assert payload["dept_id"] == str(dept_id)


# ── decode_access_token ────────────────────────────────────────────────────────

def test_decode_valid_returns_payload():
    user    = _make_user()
    token   = create_access_token(user)
    payload = decode_access_token(token)
    assert "sub" in payload
    assert "exp" in payload


def test_decode_tampered_raises():
    user  = _make_user()
    token = create_access_token(user) + "tampered"
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_decode_wrong_type_raises():
    """Refresh token must not be accepted as access token."""
    import jwt

    from config.settings import get_settings
    _settings = get_settings()
    payload = {
        "sub":       str(uuid.uuid4()),
        "type":      "refresh",   # wrong type
        "ver":       1,
        "role":      "DEVELOPER",
        "tenant_id": str(uuid.uuid4()),
        "dept_id":   None,
        "aud":       ACCESS_TOKEN_AUDIENCE,
        "iat":       datetime.datetime.now(timezone.utc),
        "exp":       datetime.datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    token = jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_algorithm)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_decode_wrong_audience_raises():
    import jwt

    from config.settings import get_settings
    _settings = get_settings()
    payload = {
        "sub":       str(uuid.uuid4()),
        "type":      "access",
        "ver":       1,
        "role":      "DEVELOPER",
        "tenant_id": str(uuid.uuid4()),
        "dept_id":   None,
        "aud":       "wrong-audience",
        "iat":       datetime.datetime.now(timezone.utc),
        "exp":       datetime.datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    token = jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_algorithm)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_decode_missing_sub_raises():
    import jwt

    from config.settings import get_settings
    _settings = get_settings()
    payload = {
        "type":      "access",
        "ver":       1,
        "role":      "DEVELOPER",
        "tenant_id": str(uuid.uuid4()),
        "dept_id":   None,
        "aud":       ACCESS_TOKEN_AUDIENCE,
        "iat":       datetime.datetime.now(timezone.utc),
        "exp":       datetime.datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    token = jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_algorithm)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_decode_missing_tenant_id_raises():
    import jwt

    from config.settings import get_settings
    _settings = get_settings()
    payload = {
        "sub":   str(uuid.uuid4()),
        "type":  "access",
        "ver":   1,
        "role":  "DEVELOPER",
        "aud":   ACCESS_TOKEN_AUDIENCE,
        "iat":   datetime.datetime.now(timezone.utc),
        "exp":   datetime.datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    token = jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_algorithm)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_decode_error_message_is_generic():
    """Error message must never leak internal details to caller."""
    with pytest.raises(InvalidTokenError) as exc_info:
        decode_access_token("not.a.valid.token")
    assert str(exc_info.value) == "Token validation failed"


# ── decode_access_token: algorithm pre-validation (C3) ─────────────────────────

def test_decode_rejects_alg_none():
    """alg=none token must be rejected pre-decode."""
    import jwt
    payload = {
        "sub":       str(uuid.uuid4()),
        "type":      "access",
        "ver":       1,
        "role":      "DEVELOPER",
        "tenant_id": str(uuid.uuid4()),
        "dept_id":   None,
        "aud":       ACCESS_TOKEN_AUDIENCE,
        "iat":       datetime.datetime.now(timezone.utc),
        "exp":       datetime.datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    token = jwt.encode(payload, key="", algorithm="none")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_decode_rejects_mismatched_algorithm():
    """Token signed with a different HMAC alg must be rejected."""
    import jwt

    from config.settings import get_settings
    _settings = get_settings()
    if _settings.jwt_algorithm == "HS512":
        pytest.skip("configured alg matches wrong-alg test candidate")
    payload = {
        "sub":       str(uuid.uuid4()),
        "type":      "access",
        "ver":       1,
        "role":      "DEVELOPER",
        "tenant_id": str(uuid.uuid4()),
        "dept_id":   None,
        "aud":       ACCESS_TOKEN_AUDIENCE,
        "iat":       datetime.datetime.now(timezone.utc),
        "exp":       datetime.datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    token = jwt.encode(payload, _settings.secret_key, algorithm="HS512")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_decode_rejects_malformed_header():
    """Garbage that is not a JWT must not crash - must raise generic error."""
    with pytest.raises(InvalidTokenError):
        decode_access_token("garbage")


# ── create_refresh_token ───────────────────────────────────────────────────────

def test_refresh_token_returns_tuple():
    result = create_refresh_token()
    assert isinstance(result, tuple)
    assert len(result) == 2


def test_refresh_raw_differs_from_hash():
    raw, hashed = create_refresh_token()
    assert raw != hashed


def test_refresh_raw_is_url_safe_string():
    raw, _ = create_refresh_token()
    assert isinstance(raw, str)
    assert len(raw) > 20


def test_hash_is_deterministic():
    raw, hashed = create_refresh_token()
    assert hash_refresh_token(raw) == hashed


def test_different_tokens_produce_different_hashes():
    _raw1, hash1 = create_refresh_token()
    _raw2, hash2 = create_refresh_token()
    assert hash1 != hash2
