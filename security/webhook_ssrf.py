# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Connect-time SSRF egress guard for outbound webhook delivery.

Distinct from security/url_validator.validate_llm_base_url on purpose. The
LLM proxy target is frequently an INTERNAL service -- pointing WrapSec at an
in-cluster Ollama/vLLM is a primary self-hosted use case -- so that validator
stays permissive. Webhook destinations are meant to reach EXTERNAL SIEMs, so
their egress is locked down secure-by-default:

  * The destination host is RESOLVED and every resolved IP is checked against
    private / loopback / link-local / reserved / multicast / unspecified
    ranges (plus known cloud-metadata hosts). This closes the "public
    hostname that resolves to an internal IP" hole a write-time literal-IP
    check cannot catch.
  * Operators who legitimately send to an on-prem SIEM add its host or CIDR to
    WEBHOOK_EGRESS_ALLOWLIST -- the GitLab/GitHub "allow local network" model.
    The default (empty allowlist) blocks every internal target.
  * https is required unless the operator relaxes it or allowlists the host.

check_egress runs at CONNECT time (delivery worker and test-send both route
through delivery_handler.send_once), so it also covers a URL that resolved
public at create time but was later repointed internally. Resolving
immediately before the request shrinks the DNS-rebinding window to near zero.
Uses ipaddress's built-in classification rather than a hardcoded range list so
IPv6, IPv4-mapped IPv6, reserved, and multicast targets are all covered.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

from config.settings import get_settings

# Cloud metadata endpoints reachable by name (the IP form 169.254.169.254 is
# caught by the link-local classification below).
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.goog"})


class WebhookEgressBlocked(Exception):
    """Raised when a webhook destination is not a permitted egress target.
    `reason` is a short, user-safe label (never includes resolved internals)."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _parse_allowlist(raw: str) -> tuple[frozenset[str], tuple]:
    """Split WEBHOOK_EGRESS_ALLOWLIST into (hostnames, ip_networks). An entry
    that parses as a CIDR/IP is a network; anything else is a hostname."""
    hosts: set[str] = set()
    nets: list = []
    for item in (raw or "").split(","):
        item = item.strip().lower()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            hosts.add(item)
    return frozenset(hosts), tuple(nets)


def _is_internal_ip(ip: ipaddress._BaseAddress) -> bool:
    # IPv4-mapped IPv6 (::ffff:10.0.0.1) must be judged on the embedded v4.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


async def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    loop  = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [ipaddress.ip_address(info[4][0]) for info in infos]


async def check_egress(url: str) -> None:
    """
    Raise WebhookEgressBlocked if `url` is not a permitted webhook target.

    Reasons: "https_required", "metadata_host", "private_address",
    "dns_resolution_failed", "no_host".
    """
    settings = get_settings()
    parsed   = urlparse(url)
    host     = (parsed.hostname or "").lower()
    if not host:
        raise WebhookEgressBlocked("no_host")

    allow_hosts, allow_nets = _parse_allowlist(settings.webhook_egress_allowlist)

    # Require https unless the host is an explicitly allowlisted internal host.
    if (
        settings.webhook_require_https
        and parsed.scheme.lower() != "https"
        and host not in allow_hosts
    ):
        raise WebhookEgressBlocked("https_required")

    if not settings.webhook_block_private_egress:
        return  # operator opted out (fully trusted network)

    if host in allow_hosts:
        return
    if host in _METADATA_HOSTS:
        raise WebhookEgressBlocked("metadata_host")

    try:
        resolved = await _resolve(host)
    except (socket.gaierror, UnicodeError, ValueError, OSError):
        # Fail closed: an unresolvable/unverifiable target is not delivered to.
        raise WebhookEgressBlocked("dns_resolution_failed") from None

    for ip in resolved:
        if any(ip in net for net in allow_nets):
            continue
        if _is_internal_ip(ip):
            raise WebhookEgressBlocked("private_address")
