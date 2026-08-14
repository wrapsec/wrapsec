# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Shared SSRF validator for LLM provider URLs.

Applied at every settings write-site that accepts a base_url / provider_url
from an admin (proxy_settings, settings.llm, departments, applications).

Rejects:
  - Any scheme other than http:// or https://
  - Hostname == "localhost" or a cloud-metadata host
  - Hostname that parses as an IP address in a private/loopback/link-local
    range (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 0/8, ::1, fe80::/10,
    fc00::/7)

Deliberately does NOT do DNS resolution:
  - Docker deployments use service names ("ollama", "api") which resolve to
    private IPs at request time. Blocking those would break the primary
    self-hosted deployment path.
  - A determined attacker could still register a public DNS name that
    resolves to a private IP. Egress firewalling at the container network
    is the correct control for that class of attack, not URL validation.
"""

import ipaddress
from urllib.parse import urlparse

_PRIVATE_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

_BLOCKED_HOSTS = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
})


def is_ssrf_target(url: str) -> bool:
    """
    True if the URL targets a private, loopback, link-local, or cloud-metadata
    address. False for public hostnames (whether or not they resolve).
    """
    host = (urlparse(url).hostname or "").lower()
    if host in _BLOCKED_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


def validate_llm_base_url(v: str) -> str:
    """
    Normalise (strip trailing slash) and SSRF-validate an LLM provider URL.
    Raises ValueError with a user-safe message on rejection.
    Returns the normalised URL on success.
    """
    v = v.rstrip("/")
    if not v.startswith(("http://", "https://")):
        raise ValueError("base_url must start with http:// or https://")
    if is_ssrf_target(v):
        raise ValueError("base_url must not target private or internal addresses")
    return v


def validate_policy_override_urls(override: dict | None) -> None:
    """SSRF-validate any base_url embedded in a policy_override's llm /
    proxy_provider sections.

    The dedicated /policy/llm and /policy/proxy PATCH endpoints validate base_url,
    but the generic policy_override on department/application create+update stores
    the dict verbatim. Call this there so both write paths enforce the same guard.
    Raises ValueError on rejection.
    """
    if not isinstance(override, dict):
        return
    for section in ("llm", "proxy_provider"):
        sub = override.get(section)
        if isinstance(sub, dict) and sub.get("base_url"):
            validate_llm_base_url(sub["base_url"])
