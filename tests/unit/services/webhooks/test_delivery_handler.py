# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.delivery_handler.send_once.

send_once is the build+send path shared by the queue handler and the
v1.3.1 test-send endpoint. These tests pin request construction per
connector, auth resolution, and the ok/permanent/transient
classification, with httpx mocked at the client boundary and no DB.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from services.webhooks import delivery_handler as dh
from services.webhooks.delivery_handler import WebhookDeliveryHandler


class _FakeResp:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class _FakeHTTPClient:
    def __init__(self, response=None, raise_exc=None):
        self.response = response
        self.raise_exc = raise_exc
        self.last = None

    async def request(self, method, url, headers=None, content=None):
        self.last = {"method": method, "url": url, "headers": headers, "content": content}
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.response


async def _noop_egress(url):
    return None


def _handler(monkeypatch, response=None, raise_exc=None):
    # decrypt(enc, key) -> strip an "enc:" prefix so fake secret_enc round-trips.
    monkeypatch.setattr(dh, "decrypt", lambda enc, key: enc.replace("enc:", ""))
    # These tests target build/send/classify, not the SSRF guard; bypass it so
    # non-resolvable test hostnames do not trip egress blocking.
    monkeypatch.setattr(dh.webhook_ssrf, "check_egress", _noop_egress)
    h = WebhookDeliveryHandler(session_factory=None, redis=object(),
                               timeout_s=10, max_response_bytes=2048)
    h._client = _FakeHTTPClient(response=response, raise_exc=raise_exc)
    return h


def _endpoint(**over):
    base = {
        "connector_type": None,
        "url": "https://recv.example/hook",
        "secret_enc": "enc:sk_secret",
        "old_secrets": [],
        "config": None,
        "headers": None,
    }
    base.update(over)
    return SimpleNamespace(**base)


_BODY = {"trace_id": "t-1", "timestamp": "2026-07-30T12:00:00Z",
         "decision": "BLOCK", "severity": "HIGH", "primary_reason": "RULE_DETECTOR"}


# --- Generic HMAC webhook ---------------------------------------------

@pytest.mark.asyncio
async def test_generic_signs_body_and_posts_raw(monkeypatch):
    h = _handler(monkeypatch, response=_FakeResp(200, "ok"))
    res = await h.send_once(_endpoint(), "wrapsec.request.blocked", _BODY, "msg-1")

    assert res.ok is True
    sent = h._client.last
    assert sent["method"] == "POST"
    assert sent["url"] == "https://recv.example/hook"
    assert "webhook-signature" in sent["headers"]
    assert sent["headers"]["webhook-id"] == "msg-1"
    # Body is the exact JSON bytes that were signed.
    assert json.loads(sent["content"]) == _BODY


# --- Connector dispatch + auth ----------------------------------------

@pytest.mark.asyncio
async def test_splunk_static_token_header(monkeypatch):
    h = _handler(monkeypatch, response=_FakeResp(200))
    ep = _endpoint(connector_type="splunk_hec", secret_enc="enc:hectok", config={})
    res = await h.send_once(ep, "wrapsec.request.blocked", _BODY, "msg-1")

    assert res.ok is True
    sent = h._client.last
    assert sent["url"].endswith("/services/collector/event")
    assert sent["headers"]["Authorization"] == "Splunk hectok"


@pytest.mark.asyncio
async def test_elastic_ndjson_apikey(monkeypatch):
    h = _handler(monkeypatch, response=_FakeResp(200))
    ep = _endpoint(connector_type="elastic_ecs", secret_enc="enc:apikeyb64",
                   config={"index": "logs-wrapsec.security-default"})
    res = await h.send_once(ep, "wrapsec.request.blocked", _BODY, "msg-1")

    assert res.ok is True
    sent = h._client.last
    assert sent["url"].endswith("/logs-wrapsec.security-default/_bulk")
    assert sent["headers"]["Authorization"] == "ApiKey apikeyb64"
    assert sent["headers"]["Content-Type"] == "application/x-ndjson"
    assert sent["content"].endswith(b"\n")  # NDJSON trailing newline


@pytest.mark.asyncio
async def test_sentinel_uses_entra_bearer(monkeypatch):
    async def _fake_token(redis, *, tenant_id, client_id, client_secret, cloud="public"):
        assert client_secret == "clientsecret"     # decrypted secret_enc
        return "bearer-xyz"
    monkeypatch.setattr(dh.azure_token, "get_access_token", _fake_token)

    h = _handler(monkeypatch, response=_FakeResp(204))
    ep = _endpoint(
        connector_type="sentinel_logs_ingestion",
        secret_enc="enc:clientsecret",
        url="https://dce.eastus-1.ingest.monitor.azure.com",
        config={"dcr_immutable_id": "dcr-1", "stream_name": "Custom-WrapSec_CL",
                "tenant_id": "tid", "client_id": "cid"},
    )
    res = await h.send_once(ep, "wrapsec.request.blocked", _BODY, "msg-1")

    assert res.ok is True
    assert h._client.last["headers"]["Authorization"] == "Bearer bearer-xyz"


# --- Error classification ---------------------------------------------

@pytest.mark.asyncio
async def test_unknown_connector_is_permanent(monkeypatch):
    h = _handler(monkeypatch, response=_FakeResp(200))
    res = await h.send_once(_endpoint(connector_type="bogus", config={}),
                            "wrapsec.request.blocked", _BODY, "msg-1")
    assert res.ok is False
    assert res.permanent is True
    assert h._client.last is None            # never sent


@pytest.mark.asyncio
async def test_missing_sentinel_config_is_permanent(monkeypatch):
    async def _fake_token(redis, **kw):
        return "bearer"
    monkeypatch.setattr(dh.azure_token, "get_access_token", _fake_token)
    h = _handler(monkeypatch, response=_FakeResp(200))
    # config lacks dcr_immutable_id/stream_name -> connector raises ValueError.
    ep = _endpoint(connector_type="sentinel_logs_ingestion", secret_enc="enc:cs",
                   config={"tenant_id": "t", "client_id": "c"})
    res = await h.send_once(ep, "wrapsec.request.blocked", _BODY, "msg-1")
    assert res.ok is False and res.permanent is True


@pytest.mark.asyncio
async def test_azure_token_error_is_transient(monkeypatch):
    async def _boom(redis, **kw):
        raise dh.azure_token.AzureTokenError("throttled")
    monkeypatch.setattr(dh.azure_token, "get_access_token", _boom)
    h = _handler(monkeypatch, response=_FakeResp(200))
    ep = _endpoint(connector_type="sentinel_logs_ingestion", secret_enc="enc:cs",
                   config={"dcr_immutable_id": "d", "stream_name": "s",
                           "tenant_id": "t", "client_id": "c"})
    res = await h.send_once(ep, "wrapsec.request.blocked", _BODY, "msg-1")
    assert res.ok is False and res.permanent is False


@pytest.mark.asyncio
async def test_non_2xx_is_transient_failure(monkeypatch):
    h = _handler(monkeypatch, response=_FakeResp(503, "unavailable"))
    res = await h.send_once(_endpoint(), "wrapsec.request.blocked", _BODY, "msg-1")
    assert res.ok is False
    assert res.permanent is False
    assert res.status_code == 503
    assert res.error == "HTTP 503"


@pytest.mark.asyncio
async def test_transport_error_is_transient(monkeypatch):
    h = _handler(monkeypatch, raise_exc=httpx.ConnectError("refused"))
    res = await h.send_once(_endpoint(), "wrapsec.request.blocked", _BODY, "msg-1")
    assert res.ok is False
    assert res.permanent is False
    assert res.error.startswith("transport:")


@pytest.mark.asyncio
async def test_response_snippet_is_bounded(monkeypatch):
    h = _handler(monkeypatch, response=_FakeResp(500, "x" * 10000))
    h._max_response_bytes = 100
    res = await h.send_once(_endpoint(), "wrapsec.request.blocked", _BODY, "msg-1")
    assert len(res.response_snippet) == 100


# --- SSRF egress guard ------------------------------------------------

@pytest.mark.asyncio
async def test_egress_blocked_is_permanent_and_never_sends(monkeypatch):
    from security.webhook_ssrf import WebhookEgressBlocked
    h = _handler(monkeypatch, response=_FakeResp(200))

    async def _block(url):
        raise WebhookEgressBlocked("private_address")
    monkeypatch.setattr(dh.webhook_ssrf, "check_egress", _block)

    res = await h.send_once(_endpoint(), "wrapsec.request.blocked", _BODY, "msg-1")
    assert res.ok is False
    assert res.permanent is True
    assert "egress blocked" in res.error
    assert h._client.last is None            # request never issued
