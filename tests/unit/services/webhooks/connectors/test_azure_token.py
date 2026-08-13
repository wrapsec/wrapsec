# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.connectors.azure_token.

The provider is on the Sentinel delivery hot path: the request shape (URL,
form body, scope), the cache read/write with an early-refresh TTL, and the
fail-soft behavior on a Redis outage are all load-bearing. httpx is mocked
at the AsyncClient boundary and Redis with AsyncMock, so these run with no
network or live Redis.
"""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import AsyncMock

import httpx
import pytest

from services.webhooks.connectors import azure_token
from services.webhooks.connectors.azure_token import (
    AzureTokenError,
    get_access_token,
)


class _FakeResp:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _FakeClient:
    """Async-context-manager stand-in for httpx.AsyncClient capturing the
    POST args and returning a canned response (or raising)."""
    last: ClassVar[dict] = {}

    def __init__(self, resp=None, raise_exc=None):
        self._resp = resp
        self._raise = raise_exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, data=None):
        _FakeClient.last = {"url": url, "data": data}
        if self._raise is not None:
            raise self._raise
        return self._resp


def _patch_httpx(monkeypatch, resp=None, raise_exc=None):
    monkeypatch.setattr(
        azure_token.httpx, "AsyncClient",
        lambda *a, **k: _FakeClient(resp=resp, raise_exc=raise_exc),
    )


def _redis(get_return=None):
    r = AsyncMock()
    r.get.return_value = get_return
    return r


_ARGS = {
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "client_id": "22222222-2222-2222-2222-222222222222",
    "client_secret": "s3cr3t",
}


# --- Cache hit --------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_hit_returns_token_without_http(monkeypatch):
    _patch_httpx(monkeypatch, resp=_FakeResp(500, {}))  # would fail if called
    redis = _redis(get_return="cached-token")

    token = await get_access_token(redis, **_ARGS)

    assert token == "cached-token"
    redis.set.assert_not_awaited()
    assert _FakeClient.last == {} or "url" not in _FakeClient.last  # no POST


# --- Cache miss -> fetch + store --------------------------------------

@pytest.mark.asyncio
async def test_cache_miss_fetches_and_caches_with_skew(monkeypatch):
    _patch_httpx(monkeypatch, resp=_FakeResp(200, {
        "access_token": "fresh-token", "token_type": "Bearer", "expires_in": 3600,
    }))
    redis = _redis(get_return=None)

    token = await get_access_token(redis, **_ARGS)

    assert token == "fresh-token"
    # TTL = expires_in - skew (300).
    redis.set.assert_awaited_once()
    _, kwargs = redis.set.await_args
    assert kwargs["ex"] == 3600 - 300


@pytest.mark.asyncio
async def test_request_shape_public_cloud(monkeypatch):
    _patch_httpx(monkeypatch, resp=_FakeResp(200, {"access_token": "t", "expires_in": 3600}))
    await get_access_token(_redis(None), **_ARGS)

    sent = _FakeClient.last
    assert sent["url"] == (
        "https://login.microsoftonline.com/"
        "11111111-1111-1111-1111-111111111111/oauth2/v2.0/token"
    )
    assert sent["data"]["client_id"] == _ARGS["client_id"]
    assert sent["data"]["client_secret"] == "s3cr3t"
    assert sent["data"]["grant_type"] == "client_credentials"
    assert sent["data"]["scope"] == "https://monitor.azure.com/.default"


# --- Sovereign clouds -------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cloud, login_host, audience",
    [
        ("usgov", "https://login.microsoftonline.us", "https://monitor.azure.us"),
        ("china", "https://login.chinacloudapi.cn",   "https://monitor.azure.cn"),
    ],
)
async def test_sovereign_cloud_host_and_audience(monkeypatch, cloud, login_host, audience):
    _patch_httpx(monkeypatch, resp=_FakeResp(200, {"access_token": "t", "expires_in": 3600}))
    await get_access_token(_redis(None), cloud=cloud, **_ARGS)

    sent = _FakeClient.last
    assert sent["url"].startswith(login_host + "/")
    assert sent["data"]["scope"] == f"{audience}/.default"


@pytest.mark.asyncio
async def test_unknown_cloud_raises(monkeypatch):
    with pytest.raises(AzureTokenError, match="unknown cloud"):
        await get_access_token(_redis(None), cloud="mars", **_ARGS)


# --- Error paths ------------------------------------------------------

@pytest.mark.asyncio
async def test_non_200_raises(monkeypatch):
    _patch_httpx(monkeypatch, resp=_FakeResp(401, {"error": "invalid_client"}))
    with pytest.raises(AzureTokenError, match="HTTP 401"):
        await get_access_token(_redis(None), **_ARGS)


@pytest.mark.asyncio
async def test_missing_access_token_raises(monkeypatch):
    _patch_httpx(monkeypatch, resp=_FakeResp(200, {"token_type": "Bearer", "expires_in": 3600}))
    with pytest.raises(AzureTokenError, match="missing access_token"):
        await get_access_token(_redis(None), **_ARGS)


@pytest.mark.asyncio
async def test_transport_error_raises(monkeypatch):
    _patch_httpx(monkeypatch, raise_exc=httpx.ConnectError("boom"))
    with pytest.raises(AzureTokenError, match="transport error"):
        await get_access_token(_redis(None), **_ARGS)


# --- Redis outage is non-fatal ----------------------------------------

@pytest.mark.asyncio
async def test_cache_read_failure_falls_through_to_fetch(monkeypatch):
    _patch_httpx(monkeypatch, resp=_FakeResp(200, {"access_token": "fresh", "expires_in": 3600}))
    redis = AsyncMock()
    redis.get.side_effect = RuntimeError("redis down")

    token = await get_access_token(redis, **_ARGS)
    assert token == "fresh"


@pytest.mark.asyncio
async def test_cache_write_failure_still_returns_token(monkeypatch):
    _patch_httpx(monkeypatch, resp=_FakeResp(200, {"access_token": "fresh", "expires_in": 3600}))
    redis = AsyncMock()
    redis.get.return_value = None
    redis.set.side_effect = RuntimeError("redis down")

    token = await get_access_token(redis, **_ARGS)
    assert token == "fresh"
