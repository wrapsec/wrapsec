"""
WrapSec asynchronous HTTP client.

Mirrors client.py exactly — same public methods, same behaviour.
Uses httpx for async HTTP instead of requests.
Delegates retry to core/retry.py (with_retry_async).

Spec reference: Section 3 (async_client.py), Section 4 (Public API Surface)
"""

from __future__ import annotations

import logging
from typing import Any

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
from wrapsec.core.validation import normalize_text, validate_input
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

        self._api_key: str | None = api_key or self._config.api_key
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
        text:    str,
        mode:    str = "fast",
        user:    str = "sdk",
        timeout: int | None = None,
    ) -> ScanResult:
        """
        Scan a single input for security risks. Async version.
        See Client.scan() for full documentation.
        """
        text = normalize_text(text)
        text = validate_input(text)
        t    = self._resolve_timeout(timeout)

        data = await self._request(
            method  = "POST",
            path    = "/ai/request",
            timeout = t,
            json    = {
                "input":          text,
                "detection_mode": mode,
                "metadata": {
                    "source":  "wrapsec-python",
                    "user_id": user,
                },
            },
        )
        return ScanResult.from_dict(data)

    async def batch(
        self,
        texts:    list[str],
        mode:     str = "fast",
        user:     str = "sdk",
        timeout:  int | None = None,
        delay_ms: int = 0,
    ) -> list[ScanResult]:
        """
        Scan multiple inputs concurrently (with optional delay).
        Returns results in the same order as inputs.
        """
        import asyncio
        results: list[ScanResult] = []
        for i, text in enumerate(texts):
            if delay_ms > 0 and i > 0:
                await asyncio.sleep(delay_ms / 1000)
            results.append(await self.scan(text, mode=mode, user=user, timeout=timeout))
        return results

    async def audit_list(
        self,
        decision:  str | None = None,
        reason:    str | None = None,
        from_date: str | None = None,
        to_date:   str | None = None,
        limit:     int = 20,
        timeout:   int | None = None,
    ) -> list[AuditLog]:
        params: dict[str, str] = {"limit": str(min(limit, 100))}
        if decision:  params["decision"] = decision
        if reason:    params["reason"]   = reason
        if from_date: params["from"]     = from_date
        if to_date:   params["to"]       = to_date

        data = await self._request("GET", "/audit/logs", self._resolve_timeout(timeout), params=params)
        return [AuditLog.from_dict(item) for item in data.get("logs", [])]

    async def audit_get(self, trace_id: str, timeout: int | None = None) -> AuditLog:
        data  = await self._request(
            "GET", "/audit/logs",
            self._resolve_timeout(timeout),
            params={"trace_id": trace_id, "limit": "1"},
        )
        items = data.get("items", data.get("logs", []))
        if not items:
            from wrapsec.exceptions import WrapSecError
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
        t          = self._resolve_timeout(timeout)
        thresholds = await self._request("GET", "/settings/thresholds", t)
        layers     = await self._request("GET", "/settings/layers",     t)
        llm        = await self._request("GET", "/settings/llm",        t)
        return {"thresholds": thresholds, "layers": layers, "llm": llm}

    async def keys_list(self, timeout: int | None = None) -> list[dict[str, Any]]:
        data = await self._request("GET", "/keys", self._resolve_timeout(timeout))
        return data.get("keys", [])

    async def health_live(self) -> bool:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                resp = await c.get(f"{self._base_url}/health/live")
                return resp.is_success
        except Exception:
            return False

    async def health_ready(self) -> dict[str, Any]:
        import httpx
        api_key = self._require_api_key()
        async with httpx.AsyncClient(timeout=5) as c:
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

    async def health_config(self) -> dict[str, Any]:
        import httpx
        api_key = self._require_api_key()
        async with httpx.AsyncClient(timeout=5) as c:
            resp = await c.get(
                f"{self._base_url}/health/config",
                headers=build_headers(api_key),
            )
        if resp.is_success:
            return resp.json()
        return {}
