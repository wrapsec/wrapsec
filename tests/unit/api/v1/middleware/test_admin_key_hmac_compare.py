# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression: admin API key must be compared with hmac.compare_digest, not ==.

Threat model: a plain `==` compare returns as soon as the first differing
byte is found. That difference in return time is enough to leak the correct
prefix of ADMIN_API_KEY one byte at a time to a remote attacker who can
measure request latency. `hmac.compare_digest` compares byte-by-byte in
constant time.

This test locks the invariant in two ways:

1. Behavioural spy: patch hmac.compare_digest in the auth middleware module,
   drive a request through _authenticate_api_key with a candidate key, and
   assert the spy saw (candidate, admin_api_key). A regression to `==` would
   leave the spy uncalled.

2. Source inspection: read the compiled source of the method and assert
   `hmac.compare_digest` appears - and that a bare `== get_settings().admin_api_key`
   does not. This catches regressions even in code paths the behavioural
   test does not exercise.
"""

import inspect
import hmac as _hmac
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.responses import Response

from api.v1.middleware import auth as auth_mw


def _fake_request(api_key: str):
    """
    Minimal Request-like stand-in exposing just the attributes
    _authenticate_api_key reads: state, headers, url.path, client.host.
    """
    class _State:
        pass

    class _URL:
        path = "/v1/keys"

    class _Client:
        host = "127.0.0.1"

    req = MagicMock()
    req.state   = _State()
    req.headers = {"x-api-key": api_key}
    req.url     = _URL()
    req.client  = _Client()
    return req


@pytest.mark.asyncio
async def test_authenticate_api_key_calls_hmac_compare_digest(monkeypatch):
    """
    The behavioural half: patch hmac.compare_digest with a spy that returns
    False (so the admin path is not taken and we do not need to wire the
    downstream admin-authenticated flow). Then assert the spy was called
    with (submitted_key, admin_api_key).
    """
    calls = []

    def _spy(a, b):
        calls.append((a, b))
        return False  # force miss so downstream fallback kicks in

    monkeypatch.setattr(auth_mw.hmac, "compare_digest", _spy)

    # Fake settings with a known admin key
    fake_settings = MagicMock()
    fake_settings.admin_api_key = "TEST_ADMIN_KEY_12345"

    with patch.object(auth_mw, "get_settings", return_value=fake_settings):
        mw       = auth_mw.AuthMiddleware(app=MagicMock())
        request  = _fake_request(api_key="wsk_live_something")
        call_next = AsyncMock(return_value=Response(content=b"", status_code=401))

        # The API key does not match a real stored key, so this path will
        # exit at "invalid_api_key". We only care that hmac.compare_digest
        # was called *before* the wsk_live_ branch.
        await mw._authenticate_api_key("wsk_live_something", request, call_next)

    assert calls, "hmac.compare_digest was never invoked - admin key path likely uses =="
    # Both operands must be the strings; order doesn't matter for compare_digest
    assert any(
        {a, b} == {"wsk_live_something", "TEST_ADMIN_KEY_12345"}
        for a, b in calls
    ), f"compare_digest called with unexpected operands: {calls}"


def test_authenticate_api_key_source_uses_hmac_compare_digest():
    """
    The static half: read the method body and assert the constant-time
    compare is textually present, and that a plain equality compare against
    admin_api_key is absent. Guards against a future edit that regresses to
    `==` even if the behavioural test above is somehow bypassed.
    """
    src = inspect.getsource(auth_mw.AuthMiddleware._authenticate_api_key)

    assert "hmac.compare_digest" in src, (
        "admin key comparison must use hmac.compare_digest for timing safety"
    )
    assert "== get_settings().admin_api_key" not in src, (
        "admin key comparison must not use ==; use hmac.compare_digest"
    )
    assert "admin_api_key ==" not in src, (
        "admin key comparison must not use ==; use hmac.compare_digest"
    )
