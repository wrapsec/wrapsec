# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec asynchronous HTTP client.

Mirrors client.py exactly - same public methods, same behaviour.
Uses httpx for async HTTP instead of requests.
Delegates retry to core/retry.py (with_retry_async).

Spec reference: Section 3 (async_client.py), Section 4 (Public API Surface)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from wrapsec.exceptions import WrapSecError

from wrapsec.config.loader import load_config
from wrapsec.config.schema import WrapSecConfig
from wrapsec.core.http import (
    BASE_PATH,
    DEFAULT_BASE_URL,
    build_headers,
    execute_request_async,
    map_response_error,
    resolve_timeout,
)
from wrapsec.core.retry import with_retry_async
from wrapsec.core.validation import (
    normalize_text,
    validate_input,
    validate_session_id,
    validate_turn_index,
)
from wrapsec.exceptions import WrapSecAuthError
from wrapsec.models import AuditLog, AuditStats, ScanResult

logger = logging.getLogger("wrapsec.async_client")


class AsyncClient:
    """
    WrapSec asynchronous API client.

    Usage:
        import wrapsec

        async with wrapsec.AsyncClient(api_key="wsk_live_...") as client:
            result = await client.scan("user input here")
            print(result.decision)

    All public methods are stable API (listed in wrapsec.__all__).

    Spec: Section 4 (Public API Surface)
    """

    def __init__(
        self,
        api_key:  str | None = None,
        base_url: str | None = None,
        timeout:  int | None = None,
    ) -> None:
        self._config: WrapSecConfig = load_config()

        self._api_key: str | None = api_key if api_key is not None else self._config.api_key
        self._base_url: str = (
            (base_url or "").rstrip("/")
            or self._config.base_url
            or DEFAULT_BASE_URL
        )

        if timeout is not None and timeout < 1:
            raise ValueError(f"timeout must be at least 1 second, got {timeout}")
        self._timeout: int | None = timeout

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass

    def _require_api_key(self) -> str:
        if not self._api_key:
            raise WrapSecAuthError(
                "No API key configured. Set it with:\n"
                "  wrapsec config set api_key <your_key>\n"
                "Or set the WRAPSEC_API_KEY environment variable."
            )
        return self._api_key

    def _url(self, path: str) -> str:
        return f"{self._base_url}{BASE_PATH}{path}"

    def _resolve_timeout(self, method_timeout: int | None) -> int:
        return resolve_timeout(
            method_timeout  = method_timeout,
            client_timeout  = self._timeout,
            config_timeout  = self._config.timeout,
            fallback        = 30,
        )

    async def _request(
        self,
        method:  str,
        path:    str,
        timeout: int,
        json:    dict[str, Any] | None = None,
        params:  dict[str, str] | None = None,
    ) -> dict[str, Any]:
        api_key = self._require_api_key()
        headers = build_headers(api_key)
        url     = self._url(path)

        return await with_retry_async(
            lambda: execute_request_async(method, url, headers, timeout, json, params),
            operation=f"{method.upper()} {path}",
        )

    # ── Public methods ──────────────────────────────────────────────────────

    async def scan(
        self,
        text:           str,
        mode:           str = "fast",
        execution_mode: str = "scan_only",
        model:          str | None = None,
        user:           str = "sdk",
        timeout:        int | None = None,
        session_id:     str | None = None,
        turn_index:     int | None = None,
        run_id:         str | None = None,
    ) -> ScanResult:
        """
        Scan a single input for security risks. Async version.
        See Client.scan() for full documentation.
        """
        _VALID_MODES = ("fast", "full")
        if mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of {_VALID_MODES}, got {mode!r}")

        _VALID_EXECUTION_MODES = ("scan_only", "proxy")
        if execution_mode not in _VALID_EXECUTION_MODES:
            raise ValueError(
                f"execution_mode must be one of {_VALID_EXECUTION_MODES}, got {execution_mode!r}"
            )
        if execution_mode == "proxy" and not model:
            raise ValueError("model is required when execution_mode='proxy'")

        session_id = validate_session_id(session_id, "session_id")
        run_id     = validate_session_id(run_id, "run_id")
        turn_index = validate_turn_index(turn_index)

        text = normalize_text(text)
        text = validate_input(text)
        t    = self._resolve_timeout(timeout)

        body: dict[str, Any] = {
            "input":          text,
            "detection_mode": mode,
            "execution_mode": execution_mode,
            "metadata": {
                "source":  "wrapsec-python",
                "user_id": user,
            },
        }
        if model:      body["model"]      = model
        if session_id: body["session_id"] = session_id
        if run_id:     body["run_id"]     = run_id
        if turn_index is not None:
            body["turn_index"] = turn_index

        data = await self._request(method="POST", path="/ai/request", timeout=t, json=body)
        return ScanResult.from_dict(data)

    async def get_request(self, trace_id: str, timeout: int | None = None) -> dict[str, Any]:
        """
        Retrieve the full audit record for a single request by trace ID.
        Includes proxy enrichment data when execution_mode is "proxy".
        Scoped to the caller's dept/tenant - 404 if out of scope.

        Returns a raw dict (structure varies by execution_mode).
        """
        return await self._request(
            "GET", f"/ai/requests/{trace_id}",
            self._resolve_timeout(timeout),
        )

    async def audit_export(
        self,
        decision:        str | None = None,
        primary_reason:  str | None = None,
        confidence_band: str | None = None,
        from_date:       str | None = None,
        to_date:         str | None = None,
        dept_id:         str | None = None,
        app_id:          str | None = None,
        limit:           int = 1000,
        timeout:         int | None = None,
    ) -> bytes:
        """
        Export audit logs as CSV bytes for compliance reporting (up to 10,000 rows).
        Scope is bounded by the API key used - non-admin keys are limited to their dept.

        Returns raw CSV bytes. Write to a file or decode as needed:
            data = await client.audit_export()
            Path("audit.csv").write_bytes(data)
        """
        api_key = self._require_api_key()
        params: dict[str, str] = {"limit": str(min(limit, 10000))}
        if decision:        params["decision"]        = decision
        if primary_reason:  params["primary_reason"]  = primary_reason
        if confidence_band: params["confidence_band"] = confidence_band
        if from_date:       params["from"]            = from_date
        if to_date:         params["to"]              = to_date
        if dept_id:         params["dept_id"]         = dept_id
        if app_id:          params["app_id"]          = app_id

        t   = self._resolve_timeout(timeout)
        url = self._url("/audit/export")
        async with httpx.AsyncClient(timeout=t) as c:
            resp = await c.get(url, headers=build_headers(api_key), params=params)
        if resp.is_success:
            return resp.content
        response_data = None
        try:
            response_data = resp.json()
        except Exception:
            pass
        raise map_response_error(resp.status_code, response_data)

    async def batch(
        self,
        texts:    list[str],
        mode:     str = "fast",
        user:     str = "sdk",
        timeout:  int | None = None,
        delay_ms: int = 0,
    ) -> list[ScanResult]:
        """
        Scan multiple inputs sequentially (with optional delay between requests).
        Returns results in the same order as inputs.
        """
        results: list[ScanResult] = []
        for i, text in enumerate(texts):
            if delay_ms > 0 and i > 0:
                await asyncio.sleep(delay_ms / 1000)
            results.append(await self.scan(text, mode=mode, user=user, timeout=timeout))
        return results

    async def audit_list(
        self,
        decision:       str | None = None,
        reason:         str | None = None,
        execution_mode: str | None = None,
        from_date:      str | None = None,
        to_date:        str | None = None,
        limit:          int = 20,
        offset:         int = 0,
        timeout:        int | None = None,
    ) -> list[AuditLog]:
        params: dict[str, str] = {"limit": str(min(limit, 100)), "offset": str(max(offset, 0))}
        if decision:        params["decision"]        = decision
        if reason:          params["primary_reason"]  = reason
        if execution_mode:  params["execution_mode"]  = execution_mode
        if from_date:       params["from"]            = from_date
        if to_date:         params["to"]              = to_date

        data = await self._request("GET", "/audit/logs", self._resolve_timeout(timeout), params=params)
        return [AuditLog.from_dict(item) for item in data.get("items", data.get("logs", []))]

    async def audit_get(self, trace_id: str, timeout: int | None = None) -> AuditLog:
        data  = await self._request(
            "GET", "/audit/logs",
            self._resolve_timeout(timeout),
            params={"trace_id": trace_id, "limit": "1"},
        )
        items = data.get("items", data.get("logs", []))
        if not items:
            raise WrapSecError(f"Audit record not found: {trace_id}")
        return AuditLog.from_dict(items[0])

    async def audit_stats(
        self,
        from_date: str | None = None,
        to_date:   str | None = None,
        timeout:   int | None = None,
    ) -> AuditStats:
        params: dict[str, str] = {}
        if from_date: params["from"] = from_date
        if to_date:   params["to"]   = to_date

        data = await self._request("GET", "/audit/stats", self._resolve_timeout(timeout), params=params)
        return AuditStats.from_dict(data)

    async def settings_get(self, timeout: int | None = None) -> dict[str, Any]:
        t           = self._resolve_timeout(timeout)
        thresholds  = await self._request("GET", "/settings/thresholds",  t)
        layers      = await self._request("GET", "/settings/layers",      t)
        llm         = await self._request("GET", "/settings/llm",         t)
        rate_limit  = await self._request("GET", "/settings/rate_limit",  t)
        return {"thresholds": thresholds, "layers": layers, "llm": llm, "rate_limit": rate_limit}

    async def keys_list(self, timeout: int | None = None) -> list[dict[str, Any]]:
        data = await self._request("GET", "/keys", self._resolve_timeout(timeout))
        return data.get("keys", [])

    async def health_live(self, timeout: int = 5) -> bool:
        """
        Check if the API is reachable (/health/live). No auth required.
        Fixed default timeout: 5s - matches sync client interface.
        """
        try:
            async with httpx.AsyncClient(timeout=timeout) as c:
                resp = await c.get(f"{self._base_url}/health/live")
                return resp.is_success
        except Exception:
            return False

    async def health_ready(self, timeout: int = 5) -> dict[str, Any]:
        """
        Check full service health (/health/ready). Auth required.
        Fixed default timeout: 5s - matches sync client interface.
        """
        api_key = self._require_api_key()
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.get(
                f"{self._base_url}/health/ready",
                headers=build_headers(api_key),
            )
        if resp.is_success:
            return resp.json()
        response_data = None
        try:
            response_data = resp.json()
        except Exception:
            pass
        raise map_response_error(resp.status_code, response_data)

    async def health_config(self, timeout: int = 5) -> dict[str, Any]:
        """
        Retrieve gateway active config. Fixed default timeout: 5s.
        """
        api_key = self._require_api_key()
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.get(
                f"{self._base_url}/health/config",
                headers=build_headers(api_key),
            )
        if resp.is_success:
            return resp.json()
        return {}
