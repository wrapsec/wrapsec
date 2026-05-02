# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Base HTTP layer — request construction, header building, timeout resolution,
error mapping from HTTP status to typed exceptions.

Shared by client.py (sync) and async_client.py (async).
All retry logic is handled by core/retry.py, not here.

Spec reference: Section 3 (core/http.py), Section 8 (SDK Error Mapping),
                Section 15 (HTTP Error Handling), Section 7 (Timeout Resolution)
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import requests
import requests.exceptions

from wrapsec.exceptions import (
    WrapSecAuthError,
    WrapSecError,
    WrapSecRateLimitError,
    WrapSecSystemError,
)

logger = logging.getLogger("wrapsec.http")

# Single constant — the ONLY place /v1 is defined in the SDK
# Spec: Section 6.5
BASE_PATH        = "/v1"
DEFAULT_BASE_URL = "http://localhost:8000"


def build_headers(api_key: str) -> dict[str, str]:
    """
    Build the standard request headers for every WrapSec API call.
    Uses x-api-key (not Bearer) — matches WrapSec API auth convention.
    Generates a unique idempotency key per request.
    """
    return {
        "x-api-key":        api_key,
        "Idempotency-Key":  str(uuid.uuid4()),
        "Content-Type":     "application/json",
        "User-Agent":       "wrapsec-python/0.1.0",
    }


def resolve_timeout(
    method_timeout:  int | None,
    client_timeout:  int | None,
    config_timeout:  int | None,
    fallback:        int = 30,
) -> int:
    """
    Resolve timeout using strict is not None chain.
    Never uses falsy check — timeout=0 would cause indefinite hangs.

    Priority: method argument → client default → config → fallback (30s)

    Spec: Section 7 (Timeout Resolution)
    """
    t = (
        method_timeout  if method_timeout  is not None
        else client_timeout if client_timeout is not None
        else config_timeout if config_timeout is not None
        else fallback
    )
    if t < 1:
        raise ValueError(f"timeout must be at least 1 second, got {t}")
    return t


def map_response_error(
    status_code: int,
    response_data: dict[str, Any] | None,
    raw_text: str = "",
) -> WrapSecError:
    """
    Map an HTTP error status code to the appropriate typed exception.
    Returns the exception — does not raise. Caller decides when to raise.

    Spec: Section 8 (SDK Error Mapping), Section 15 (HTTP Error Handling)
    """
    error_detail = ""
    if response_data:
        err = response_data.get("error", {})
        error_detail = err.get("message", "") if isinstance(err, dict) else ""

    if status_code in (401, 403):
        msg = (
            "Invalid or revoked API key. Run: wrapsec config set api_key <key>"
            if status_code == 401
            else "Permission denied."
        )
        return WrapSecAuthError(msg, status_code=status_code, response=response_data)

    if status_code == 404:
        return WrapSecError(
            "Endpoint not found. Check your base_url or run wrapsec doctor.",
            status_code=status_code,
            response=response_data,
        )

    if status_code == 413:
        return WrapSecError(
            "Input too large. Max payload is 64KB.",
            status_code=status_code,
            response=response_data,
        )

    if status_code == 422:
        msg = error_detail or "Request validation failed."
        return WrapSecError(msg, status_code=status_code, response=response_data)

    if status_code == 429:
        return WrapSecRateLimitError(
            "Rate limit exceeded. Try again later, or use --delay to slow batch requests.",
            status_code=status_code,
            response=response_data,
        )

    if status_code >= 500:
        return WrapSecSystemError(
            f"Server error ({status_code}). WrapSec API is experiencing issues.",
            status_code=status_code,
            response=response_data,
        )

    # Bug #5 fix: never include raw response text in the error message.
    # raw_text could be an HTML error page containing internal server paths,
    # stack traces, or infrastructure details. Log it internally instead.
    import logging as _logging
    _logging.getLogger("wrapsec.http").debug(
        "Unexpected HTTP %d raw response: %s", status_code, raw_text[:500]
    )
    return WrapSecError(
        f"Unexpected HTTP {status_code}{': ' + error_detail if error_detail else ''}",
        status_code=status_code,
        response=response_data,
    )


def execute_request(
    method:   str,
    url:      str,
    headers:  dict[str, str],
    timeout:  int,
    json:     dict[str, Any] | None = None,
    params:   dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Execute a synchronous HTTP request and return the parsed JSON body.

    Raises typed WrapSecError subclasses on all error conditions.
    Raises WrapSecSystemError for timeout, connection, and JSON parse errors.
    Does NOT retry — retry is handled by core/retry.py.

    Spec: Section 3 (core/http.py — shared by sync and async clients)
    """
    try:
        resp = requests.request(
            method  = method.upper(),
            url     = url,
            headers = headers,
            json    = json,
            params  = params,
            timeout = timeout,
        )
    except requests.exceptions.Timeout:
        raise WrapSecSystemError(
            f"Request timed out after {timeout}s. Increase with --timeout.",
        )
    except requests.exceptions.ConnectionError:
        raise WrapSecSystemError(
            "Cannot reach WrapSec API. Check your network connection and base_url.",
        )
    except requests.exceptions.RequestException as e:
        raise WrapSecSystemError(f"Request failed: {e}")

    # Parse response body
    response_data: dict[str, Any] | None = None
    try:
        response_data = resp.json()
    except Exception:
        if not resp.ok:
            raise WrapSecSystemError(
                "Invalid response from API.",
                status_code=resp.status_code,
            )

    if not resp.ok:
        raise map_response_error(resp.status_code, response_data, resp.text)

    return response_data or {}


async def execute_request_async(
    method:   str,
    url:      str,
    headers:  dict[str, str],
    timeout:  int,
    json:     dict[str, Any] | None = None,
    params:   dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Execute an asynchronous HTTP request using httpx.
    Returns the parsed JSON body.

    Raises the same typed exceptions as execute_request.
    Does NOT retry — retry is handled by core/retry.py (with_retry_async).

    Spec: Section 3 (core/http.py — shared by sync and async clients)
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.request(
                method  = method.upper(),
                url     = url,
                headers = headers,
                json    = json,
                params  = params,
            )
    except httpx.TimeoutException:
        raise WrapSecSystemError(
            f"Request timed out after {timeout}s. Increase with --timeout.",
        )
    except httpx.ConnectError:
        raise WrapSecSystemError(
            "Cannot reach WrapSec API. Check your network connection and base_url.",
        )
    except httpx.RequestError as e:
        raise WrapSecSystemError(f"Request failed: {e}")

    response_data: dict[str, Any] | None = None
    try:
        response_data = resp.json()
    except Exception:
        if not resp.is_success:
            raise WrapSecSystemError(
                "Invalid response from API.",
                status_code=resp.status_code,
            )

    if not resp.is_success:
        raise map_response_error(resp.status_code, response_data, resp.text)

    return response_data or {}
