# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
M5 regression: refresh_token cookie Path resolution.

Prior state: BFF (dashboard) regex-parsed the backend Set-Cookie header
and re-emitted it with `Path=/api/auth`. Silent breakage on any backend
change to attribute encoding (new SameSite value, Partitioned, etc.).

Fix: backend accepts `X-Refresh-Cookie-Path` header, gated on:
  (1) `Origin` header present
  (2) `Origin` value in `settings.cors_allowed_origins`
  (3) header value passes _valid_cookie_path
Fall-through returns `settings.refresh_cookie_path` (default "/v1/auth").

These tests pin every gate independently so a regression that weakens
any one condition (skipped Origin check, laxer validation, etc.) fails
loudly. The Origin allowlist is defense-in-depth; the primary defense
against cookie hijacking remains HttpOnly + Secure + SameSite=strict.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from api.v1.endpoints.auth import (
    _resolve_refresh_cookie_path,
    _valid_cookie_path,
)


# ── path validation ─────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/",
    "/api/auth",
    "/v1/auth",
    "/api/v2/auth",
    "/a-b_c/d",
])
def test_valid_cookie_path_accepts_legit_paths(path):
    assert _valid_cookie_path(path) is True


@pytest.mark.parametrize("path", [
    "",                        # empty
    "api/auth",                # missing leading slash
    "/api/../etc/passwd",      # traversal
    "/api//auth",              # empty segment
    "/api/auth?x=1",           # query string
    "/api/auth;x=1",           # cookie-attr injection
    "/api/auth\r\nSet",        # CRLF injection
    "/api auth",               # space
    "/api/auth<script>",       # tag
    "/api/" + "a" * 200,       # over length cap (128)
])
def test_valid_cookie_path_rejects_bad_paths(path):
    assert _valid_cookie_path(path) is False


def test_valid_cookie_path_bounded_length():
    # exactly at the boundary
    assert _valid_cookie_path("/" + "a" * 127) is True
    assert _valid_cookie_path("/" + "a" * 128) is False


# ── _resolve_refresh_cookie_path gating ─────────────────────────────────

def _make_request(headers: dict):
    """Minimal shape needed: request.headers.get(key)."""
    class _H:
        def __init__(self, d):
            self._d = {k.lower(): v for k, v in d.items()}
        def get(self, key, default=None):
            return self._d.get(key.lower(), default)
    return SimpleNamespace(headers=_H(headers))


def _settings_with(allowlist: list[str], default_path: str = "/v1/auth"):
    return SimpleNamespace(
        cors_allowed_origins = allowlist,
        refresh_cookie_path  = default_path,
    )


def test_resolver_returns_default_when_request_is_none():
    with patch("config.settings.get_settings",
               return_value=_settings_with(["https://dashboard.example.com"])):
        assert _resolve_refresh_cookie_path(None) == "/v1/auth"


def test_resolver_returns_default_when_no_header():
    req = _make_request({"origin": "https://dashboard.example.com"})
    with patch("config.settings.get_settings",
               return_value=_settings_with(["https://dashboard.example.com"])):
        assert _resolve_refresh_cookie_path(req) == "/v1/auth"


def test_resolver_returns_default_when_header_but_no_origin():
    """Header alone must NOT be enough - Origin gate is load-bearing."""
    req = _make_request({"x-refresh-cookie-path": "/api/auth"})
    with patch("config.settings.get_settings",
               return_value=_settings_with(["https://dashboard.example.com"])):
        assert _resolve_refresh_cookie_path(req) == "/v1/auth"


def test_resolver_returns_default_when_origin_not_allowlisted():
    """Origin present but not in the allowlist - header must be ignored."""
    req = _make_request({
        "origin":                "https://attacker.example.com",
        "x-refresh-cookie-path": "/api/auth",
    })
    with patch("config.settings.get_settings",
               return_value=_settings_with(["https://dashboard.example.com"])):
        assert _resolve_refresh_cookie_path(req) == "/v1/auth"


def test_resolver_returns_default_when_allowlist_empty():
    """
    Empty allowlist = credentialed CORS disabled. Header cannot override.
    Any Origin fails the `in` check.
    """
    req = _make_request({
        "origin":                "https://dashboard.example.com",
        "x-refresh-cookie-path": "/api/auth",
    })
    with patch("config.settings.get_settings",
               return_value=_settings_with([])):
        assert _resolve_refresh_cookie_path(req) == "/v1/auth"


def test_resolver_honors_header_when_origin_allowlisted():
    req = _make_request({
        "origin":                "https://dashboard.example.com",
        "x-refresh-cookie-path": "/api/auth",
    })
    with patch("config.settings.get_settings",
               return_value=_settings_with(["https://dashboard.example.com"])):
        assert _resolve_refresh_cookie_path(req) == "/api/auth"


def test_resolver_origin_match_is_case_sensitive_exact():
    """
    RFC 6454 says Origin is a case-sensitive tuple. Do NOT normalise
    - a case difference between allowlist and header is a config bug,
    not a match.
    """
    req = _make_request({
        "origin":                "https://Dashboard.Example.Com",
        "x-refresh-cookie-path": "/api/auth",
    })
    with patch("config.settings.get_settings",
               return_value=_settings_with(["https://dashboard.example.com"])):
        assert _resolve_refresh_cookie_path(req) == "/v1/auth"


@pytest.mark.parametrize("bad_path", [
    "/api/../etc",       # traversal
    "/api//auth",        # empty segment
    "api/auth",          # missing leading slash
    "/api auth",         # space
    "/api/auth?x=1",     # query
    "/api/auth;x=1",     # attribute injection
    "/api/auth\r\nHi",   # CRLF header injection
    "",                  # empty
    "/" + "z" * 200,     # over length cap
])
def test_resolver_returns_default_when_header_fails_validation(bad_path):
    req = _make_request({
        "origin":                "https://dashboard.example.com",
        "x-refresh-cookie-path": bad_path,
    })
    with patch("config.settings.get_settings",
               return_value=_settings_with(["https://dashboard.example.com"])):
        assert _resolve_refresh_cookie_path(req) == "/v1/auth"


def test_resolver_uses_configured_default_not_hardcoded():
    """
    If an operator sets REFRESH_COOKIE_PATH=/custom/auth, that must
    surface as the fallback - not the historical hardcoded "/v1/auth".
    """
    with patch("config.settings.get_settings",
               return_value=_settings_with(
                   allowlist    = ["https://dashboard.example.com"],
                   default_path = "/custom/auth",
               )):
        assert _resolve_refresh_cookie_path(None) == "/custom/auth"


def test_resolver_default_when_all_gates_pass_except_validation():
    """
    Composite: origin allowlisted, header present, but header
    invalid - must fall back to configured default, NOT to header value.
    """
    req = _make_request({
        "origin":                "https://dashboard.example.com",
        "x-refresh-cookie-path": "/api/../attacker",
    })
    with patch("config.settings.get_settings",
               return_value=_settings_with(
                   allowlist    = ["https://dashboard.example.com"],
                   default_path = "/v1/auth",
               )):
        assert _resolve_refresh_cookie_path(req) == "/v1/auth"
