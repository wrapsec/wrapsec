# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
H5: X-Forwarded-For trust hardening tests.

get_client_ip must only trust the XFF header when the immediate peer IP
matches TRUSTED_PROXY_IPS. Otherwise attackers spoof source IPs to bypass
IP-based rate limits (login lockout, global rate limit) and inject fake
IPs into audit logs.
"""

from unittest.mock import MagicMock, patch

from api.v1.middleware.auth import get_client_ip


def _make_request(peer_ip: str, xff: str | None = None):
    req = MagicMock()
    req.client = MagicMock()
    req.client.host = peer_ip
    req.headers = {"x-forwarded-for": xff} if xff else {}
    return req


def _patch_trusted(trusted: str):
    """Patch get_settings().trusted_proxy_ips."""
    fake = MagicMock()
    fake.trusted_proxy_ips = trusted
    return patch("api.v1.middleware.auth.get_settings", return_value=fake)


def test_no_xff_returns_peer_ip():
    with _patch_trusted("10.0.0.1"):
        assert get_client_ip(_make_request("203.0.113.5")) == "203.0.113.5"


def test_xff_ignored_when_trusted_ips_unset():
    with _patch_trusted(""):
        req = _make_request("203.0.113.5", "1.2.3.4")
        assert get_client_ip(req) == "203.0.113.5"


def test_xff_ignored_when_peer_not_in_trusted_set():
    with _patch_trusted("10.0.0.1"):
        req = _make_request("203.0.113.5", "1.2.3.4")
        assert get_client_ip(req) == "203.0.113.5"


def test_xff_trusted_when_peer_matches_trusted_ip():
    with _patch_trusted("10.0.0.1"):
        req = _make_request("10.0.0.1", "203.0.113.5")
        assert get_client_ip(req) == "203.0.113.5"


def test_xff_trusted_when_peer_in_trusted_cidr():
    with _patch_trusted("10.0.0.0/8"):
        req = _make_request("10.42.7.1", "203.0.113.5")
        assert get_client_ip(req) == "203.0.113.5"


def test_xff_takes_first_hop_only():
    """Multi-hop XFF chain: only the first (leftmost) address is used."""
    with _patch_trusted("10.0.0.1"):
        req = _make_request("10.0.0.1", "203.0.113.5, 10.0.0.9, 172.16.1.2")
        assert get_client_ip(req) == "203.0.113.5"


def test_multiple_trusted_entries():
    with _patch_trusted("10.0.0.1,172.16.0.0/12"):
        req = _make_request("172.16.5.5", "8.8.8.8")
        assert get_client_ip(req) == "8.8.8.8"


def test_invalid_trusted_entry_is_skipped_but_valid_still_applies():
    with _patch_trusted("not-an-ip,10.0.0.1"):
        req = _make_request("10.0.0.1", "8.8.8.8")
        assert get_client_ip(req) == "8.8.8.8"


def test_peer_ip_unparseable_falls_back_to_peer():
    with _patch_trusted("10.0.0.1"):
        req = _make_request("garbage", "8.8.8.8")
        assert get_client_ip(req) == "garbage"


def test_no_request_client_returns_unknown():
    with _patch_trusted("10.0.0.1"):
        req = MagicMock()
        req.client = None
        req.headers = {}
        assert get_client_ip(req) == "unknown"
