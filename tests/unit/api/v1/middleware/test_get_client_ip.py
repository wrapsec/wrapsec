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


def test_spoofed_leftmost_xff_is_not_honored():
    """B3: a reverse proxy APPENDS the real peer, so the rightmost entry is
    authoritative. A client-forged leftmost value must be ignored."""
    with _patch_trusted("10.0.0.1"):
        # client forged "1.2.3.4"; the trusted proxy appended the real peer.
        req = _make_request("10.0.0.1", "1.2.3.4, 8.8.8.8")
        assert get_client_ip(req) == "8.8.8.8"


def test_rightmost_untrusted_hop_selected_through_proxy_chain():
    """Multiple trusted-proxy hops: skip trusted entries from the right and
    return the first untrusted address (the real client)."""
    with _patch_trusted("10.0.0.0/8"):
        # client(203.0.113.5) -> proxyA(10.0.0.9) -> proxyB(10.0.0.1) -> server
        req = _make_request("10.0.0.1", "203.0.113.5, 10.0.0.9")
        assert get_client_ip(req) == "203.0.113.5"


def test_all_trusted_chain_falls_back_to_peer():
    """If every forwarded entry is a trusted proxy, fall back to the direct peer
    rather than trusting a proxy IP as the client."""
    with _patch_trusted("10.0.0.0/8"):
        req = _make_request("10.0.0.1", "10.0.0.5, 10.0.0.9")
        assert get_client_ip(req) == "10.0.0.1"


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


# ── zero-prefix entries are not a restriction ────────────────────────────────
#
# `0.0.0.0/0` parses cleanly and reads like configuration, so without a guard it
# would trust a forwarded header from ANY peer while the setting looked set --
# the spoofing this list exists to prevent, with the control appearing enabled.
# `security/ip_allowlist.py::normalize_entries` rejects the same shape on
# credential allowlists; these pin the matching behaviour here.

def test_ipv4_default_route_is_ignored_not_trusted():
    with _patch_trusted("0.0.0.0/0"):
        req = _make_request("203.0.113.5", "1.2.3.4")
        assert get_client_ip(req) == "203.0.113.5", (
            "0.0.0.0/0 made every peer a trusted proxy"
        )


def test_ipv6_default_route_is_ignored_not_trusted():
    with _patch_trusted("::/0"):
        req = _make_request("2001:db8::5", "1.2.3.4")
        assert get_client_ip(req) == "2001:db8::5"


def test_a_zero_prefix_entry_does_not_disable_the_valid_ones():
    """One bad entry must not take the rest of the list with it."""
    with _patch_trusted("0.0.0.0/0,10.0.0.1"):
        # Peer IS a legitimate trusted proxy: the forwarded address is used.
        assert get_client_ip(_make_request("10.0.0.1", "203.0.113.9")) == "203.0.113.9"
        # Peer is not: the zero-prefix entry must not make it trusted.
        assert get_client_ip(_make_request("198.51.100.7", "1.2.3.4")) == "198.51.100.7"


def test_zero_prefix_written_as_a_bare_address_is_still_ignored():
    """`0.0.0.0` normalises to a /32, which is a real single-host entry and
    must keep working -- only an actual zero prefix is dropped."""
    with _patch_trusted("0.0.0.0"):
        assert get_client_ip(_make_request("0.0.0.0", "203.0.113.9")) == "203.0.113.9"


def test_a_malformed_forwarded_entry_falls_back_to_the_peer():
    """
    Behind a trusted proxy the leftmost entries are still client-controlled, so
    the selected candidate has to be a well-formed address before it is trusted.
    Without that check an arbitrary string becomes the recorded and enforced
    client address: it is written to the audit trail, matched against a key's
    ip_allowlist, and used as the per-IP rate-limit bucket, which lets a caller
    pick its own bucket.
    """
    with _patch_trusted("10.0.0.1"):
        req = _make_request("10.0.0.1", "not-an-ip-address")
        assert get_client_ip(req) == "10.0.0.1"


def test_a_malformed_entry_behind_a_trusted_hop_also_falls_back():
    """The same value reached by walking past a trusted proxy hop."""
    with _patch_trusted("10.0.0.0/24"):
        req = _make_request("10.0.0.1", "'; DROP TABLE audit_logs; --, 10.0.0.9")
        assert get_client_ip(req) == "10.0.0.1"
