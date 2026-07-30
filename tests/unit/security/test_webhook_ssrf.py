# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for security.webhook_ssrf.check_egress.

The guard is the connect-time SSRF control for webhook egress. Tests use IP
literals (getaddrinfo parses them without a network lookup) and a mocked
resolver for the hostname-resolves-to-private case, so they run offline.
"""

from __future__ import annotations

import ipaddress

import pytest

from security import webhook_ssrf as w
from security.webhook_ssrf import WebhookEgressBlocked, check_egress


class _Settings:
    def __init__(self, block=True, allowlist="", https=True):
        self.webhook_block_private_egress = block
        self.webhook_egress_allowlist     = allowlist
        self.webhook_require_https         = https


def _patch(monkeypatch, **kw):
    monkeypatch.setattr(w, "get_settings", lambda: _Settings(**kw))


async def _reason(url) -> str | None:
    try:
        await check_egress(url)
        return None
    except WebhookEgressBlocked as exc:
        return exc.reason


# --- default (secure) posture -----------------------------------------

@pytest.mark.asyncio
async def test_public_https_ip_allowed(monkeypatch):
    _patch(monkeypatch)
    assert await _reason("https://8.8.8.8/hook") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "https://10.0.0.5:9243",       # private
    "https://192.168.1.10/hook",   # private
    "https://172.16.5.5/hook",     # private
    "https://127.0.0.1/hook",      # loopback
    "https://169.254.169.254/",    # link-local / cloud metadata
    "https://[::1]/hook",          # ipv6 loopback
    "https://0.0.0.0/hook",        # unspecified
])
async def test_internal_ip_literals_blocked(monkeypatch, url):
    _patch(monkeypatch)
    assert await _reason(url) == "private_address"


@pytest.mark.asyncio
async def test_metadata_hostname_blocked(monkeypatch):
    _patch(monkeypatch)
    assert await _reason("https://metadata.google.internal/") == "metadata_host"


@pytest.mark.asyncio
async def test_http_requires_https_by_default(monkeypatch):
    _patch(monkeypatch)
    assert await _reason("http://8.8.8.8/hook") == "https_required"


@pytest.mark.asyncio
async def test_no_host_blocked(monkeypatch):
    _patch(monkeypatch)
    assert await _reason("https:///nohost") == "no_host"


# --- the key case: public hostname that RESOLVES to a private IP -------

@pytest.mark.asyncio
async def test_hostname_resolving_to_private_is_blocked(monkeypatch):
    _patch(monkeypatch)
    async def _fake_resolve(host):
        return [ipaddress.ip_address("10.1.2.3")]
    monkeypatch.setattr(w, "_resolve", _fake_resolve)
    assert await _reason("https://looks-public.example/hook") == "private_address"


@pytest.mark.asyncio
async def test_dns_failure_fails_closed(monkeypatch):
    _patch(monkeypatch)
    async def _boom(host):
        raise __import__("socket").gaierror("nope")
    monkeypatch.setattr(w, "_resolve", _boom)
    assert await _reason("https://does-not-exist.example/") == "dns_resolution_failed"


# --- operator allowlist (on-prem SIEM) --------------------------------

@pytest.mark.asyncio
async def test_allowlisted_host_exempts_including_http(monkeypatch):
    _patch(monkeypatch, allowlist="siem.internal")
    # allowlisted host bypasses both the https requirement and the private block
    assert await _reason("http://siem.internal:8088/services/collector") is None


@pytest.mark.asyncio
async def test_allowlisted_cidr_exempts_resolved_ip(monkeypatch):
    _patch(monkeypatch, allowlist="10.0.0.0/8")
    assert await _reason("https://10.0.0.5:9243") is None


@pytest.mark.asyncio
async def test_allowlist_does_not_exempt_other_private_ips(monkeypatch):
    _patch(monkeypatch, allowlist="10.0.0.0/8")
    assert await _reason("https://192.168.1.1/") == "private_address"


# --- operator opt-out --------------------------------------------------

@pytest.mark.asyncio
async def test_block_disabled_allows_private_https(monkeypatch):
    _patch(monkeypatch, block=False)
    assert await _reason("https://10.0.0.5/hook") is None


@pytest.mark.asyncio
async def test_require_https_disabled_allows_http_public(monkeypatch):
    _patch(monkeypatch, https=False)
    assert await _reason("http://8.8.8.8/hook") is None
