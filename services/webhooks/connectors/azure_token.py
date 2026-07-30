# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Microsoft Entra bearer-token provider for the Sentinel connector (v1.3.0).

The Sentinel Logs Ingestion connector authenticates with an OAuth2
client-credentials bearer token, not a static header. This module
acquires that token from Microsoft Entra and caches it in Redis so the
delivery worker does not hit the token endpoint on every event.

Token endpoint (verified against Microsoft docs):

    POST https://{login_host}/{tenant}/oauth2/v2.0/token
    Content-Type: application/x-www-form-urlencoded

    client_id={client_id}
    &scope={audience}/.default
    &client_secret={client_secret}     (url-encoded by httpx)
    &grant_type=client_credentials

Successful response is JSON with access_token, token_type ("Bearer"),
and expires_in (seconds). Client credentials never returns a refresh
token -- a fresh token is requested when the cached one nears expiry.

Cache: one entry per (tenant, client, cloud) app registration, keyed on
the non-secret tenant/client GUIDs. The Redis TTL is expires_in minus a
safety skew so a token is refreshed slightly before it actually expires,
never handed out already-dead. The shared Redis client is fine here --
these are non-blocking GET/SET, unlike the delivery worker's blocking
stream read (which needs its own connection).

Sovereign clouds change both the login host and the Azure Monitor
audience; `cloud` selects the matching pair.
"""

from __future__ import annotations

import logging

import httpx
from redis.asyncio import Redis

logger = logging.getLogger("wrapsec.webhook_azure_token")


# login host + Azure Monitor audience per cloud. scope = audience + "/.default".
_CLOUDS: dict[str, tuple[str, str]] = {
    "public": ("https://login.microsoftonline.com", "https://monitor.azure.com"),
    "usgov":  ("https://login.microsoftonline.us",  "https://monitor.azure.us"),
    "china":  ("https://login.chinacloudapi.cn",    "https://monitor.azure.cn"),
}

_CACHE_PREFIX = "wrapsec:webhook:azure_token:"

# Refresh this many seconds before the token's real expiry so a cached
# token is never returned within its last moments (clock skew, in-flight
# request time). Entra tokens live ~3600s, so 300s is a comfortable margin.
_EXPIRY_SKEW_S = 300

# Bound the token request so a hung Entra endpoint cannot stall delivery.
_REQUEST_TIMEOUT_S = 10.0

# Fallback lifetime if the response omits expires_in (should not happen).
_DEFAULT_EXPIRES_IN = 3599


class AzureTokenError(Exception):
    """Raised when an Entra token cannot be acquired. Transient by
    nature (network / 5xx / throttling), so the delivery handler treats
    it as a retryable failure rather than a dead-letter."""


def _cache_key(tenant_id: str, client_id: str, cloud: str) -> str:
    # tenant_id and client_id are non-secret GUIDs; safe and debuggable to
    # embed. The client secret is never part of the key.
    return f"{_CACHE_PREFIX}{tenant_id}:{client_id}:{cloud}"


async def get_access_token(
    redis:         Redis,
    *,
    tenant_id:     str,
    client_id:     str,
    client_secret: str,
    cloud:         str = "public",
) -> str:
    """
    Return a valid Azure Monitor bearer token for this app registration,
    from the Redis cache when warm or freshly acquired from Entra.

    Raises AzureTokenError for an unknown cloud or a failed token request.
    A Redis outage is non-fatal: the token is fetched directly and the
    cache write is best-effort.
    """
    if cloud not in _CLOUDS:
        raise AzureTokenError(f"unknown cloud: {cloud!r}")

    key = _cache_key(tenant_id, client_id, cloud)

    try:
        cached = await redis.get(key)
    except Exception as exc:                                # noqa: BLE001
        # Cache read failure must not break delivery -- fetch directly.
        logger.warning("azure token cache read failed: %s", exc)
        cached = None
    if cached:
        return cached

    login_host, audience = _CLOUDS[cloud]
    token, expires_in = await _fetch_token(
        login_host    = login_host,
        audience      = audience,
        tenant_id     = tenant_id,
        client_id     = client_id,
        client_secret = client_secret,
    )

    ttl = max(1, expires_in - _EXPIRY_SKEW_S)
    try:
        await redis.set(key, token, ex=ttl)
    except Exception as exc:                                # noqa: BLE001
        logger.warning("azure token cache write failed: %s", exc)

    return token


async def _fetch_token(
    *,
    login_host:    str,
    audience:      str,
    tenant_id:     str,
    client_id:     str,
    client_secret: str,
) -> tuple[str, int]:
    """
    POST the client-credentials request and return (access_token,
    expires_in). Raises AzureTokenError on any non-2xx or malformed
    response. The client secret is sent in the form body (httpx
    url-encodes it) and is never logged.
    """
    url  = f"{login_host}/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id":     client_id,
        "scope":         f"{audience}/.default",
        "client_secret": client_secret,
        "grant_type":    "client_credentials",
    }

    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_S) as client:
            resp = await client.post(url, data=data)
    except httpx.HTTPError as exc:
        raise AzureTokenError(f"token request transport error: {exc}") from exc

    if resp.status_code != 200:
        # The error body carries error/error_description but no secret; keep
        # the log terse and let the handler decide on retry.
        raise AzureTokenError(f"token request failed: HTTP {resp.status_code}")

    try:
        body = resp.json()
    except ValueError as exc:
        raise AzureTokenError("token response was not JSON") from exc

    token = body.get("access_token")
    if not token:
        raise AzureTokenError("token response missing access_token")

    try:
        expires_in = int(body.get("expires_in", _DEFAULT_EXPIRES_IN))
    except (TypeError, ValueError):
        expires_in = _DEFAULT_EXPIRES_IN

    return token, expires_in
