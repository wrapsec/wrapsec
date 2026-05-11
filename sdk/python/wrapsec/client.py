# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec synchronous HTTP client.

Responsibilities:
  - API interaction only: HTTP calls, response parsing, returning models
  - No CLI logic, no print statements, no spinners
  - Delegates retry to core/retry.py
  - Delegates HTTP to core/http.py
  - Delegates validation to core/validation.py
  - Reads config from config/loader.py

Spec reference: Section 3 (client.py), Section 4 (Public API Surface),
                Section 6.5 (BASE_PATH, DEFAULT_BASE_URL),
                Section 7 (Timeout Resolution)
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from wrapsec.exceptions import WrapSecError

from wrapsec.config.loader import load_config
from wrapsec.config.schema import WrapSecConfig
from wrapsec.core.http import (
    BASE_PATH,
    DEFAULT_BASE_URL,
    build_headers,
    execute_request,
    map_response_error,
    resolve_timeout,
)
from wrapsec.core.retry import with_retry
from wrapsec.core.validation import normalize_text, validate_input
from wrapsec.exceptions import WrapSecAuthError
from wrapsec.models import AuditLog, AuditStats, ScanResult

logger = logging.getLogger("wrapsec.client")


class Client:
    """
    WrapSec synchronous API client.

    Usage:
        import wrapsec

        client = wrapsec.Client(api_key="wsk_live_...")
        result = client.scan("user input here")
        print(result.decision)   # "ALLOW" | "BLOCK" | "SANITIZE"

    All public methods are stable API (listed in wrapsec.__all__).
    Internal helpers are prefixed with _.

    Spec: Section 4 (Public API Surface)
    """

    def __init__(
        self,
        api_key:  str | None = None,
        base_url: str | None = None,
        timeout:  int | None = None,
    ) -> None:
        """
        Initialise the client.

        api_key:  WrapSec API key (wsk_live_...).
                  Falls back to WRAPSEC_API_KEY env var or config file.
        base_url: WrapSec API base URL.
                  Defaults to http://localhost:8000 (development only).
                  Always set explicitly in production via WRAPSEC_BASE_URL.
        timeout:  Default request timeout in seconds (min 1, default 30).
                  Override per-request with scan(timeout=...).

        Spec: Section 7 (Timeout Resolution)
        """
        self._config: WrapSecConfig = load_config()

        # Resolve api_key: constructor arg -> env/file (already in config)
        self._api_key: str | None = api_key if api_key is not None else self._config.api_key

        # Resolve base_url: constructor arg -> env/file -> default
        self._base_url: str = (
            (base_url or "").rstrip("/")
            or self._config.base_url
            or DEFAULT_BASE_URL
        )

        # Resolve client-level timeout using is not None chain
        # Spec: Section 7
        if timeout is not None and timeout < 1:
            raise ValueError(f"timeout must be at least 1 second, got {timeout}")
        self._timeout: int | None = timeout

    def _require_api_key(self) -> str:
        if not self._api_key:
            raise WrapSecAuthError(
                "No API key configured. Set it with:\n"
                "  wrapsec config set api_key <your_key>\n"
                "Or set the WRAPSEC_API_KEY environment variable."
            )
        return self._api_key

    def _url(self, path: str) -> str:
        """Build full URL. BASE_PATH is defined only here."""
        return f"{self._base_url}{BASE_PATH}{path}"

    def _resolve_timeout(self, method_timeout: int | None) -> int:
        """
        Resolve timeout for a single request using the spec priority chain.
        Spec: Section 7
        """
        return resolve_timeout(
            method_timeout  = method_timeout,
            client_timeout  = self._timeout,
            config_timeout  = self._config.timeout,
            fallback        = 30,
        )

    def _request(
        self,
        method:  str,
        path:    str,
        timeout: int,
        json:    dict[str, Any] | None = None,
        params:  dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute a request with retry. Internal only."""
        api_key = self._require_api_key()
        headers = build_headers(api_key)
        url     = self._url(path)

        return with_retry(
            lambda: execute_request(method, url, headers, timeout, json, params),
            operation=f"{method.upper()} {path}",
        )

    # ── Public methods ──────────────────────────────────────────────────────

    def scan(
        self,
        text:           str,
        mode:           str = "fast",
        execution_mode: str = "scan_only",
        model:          str | None = None,
        user:           str = "sdk",
        timeout:        int | None = None,
    ) -> ScanResult:
        """
        Scan a single input for security risks.

        text:           The prompt or user input to scan. Max 8000 chars.
        mode:           "fast" (default) or "full" (adds LLM analysis, ~100-500ms extra).
        execution_mode: "scan_only" (default) or "proxy" (scan + forward to LLM provider).
        model:          LLM model identifier - required when execution_mode="proxy".
        user:           User ID for audit attribution. Defaults to "sdk".
                        CLI overrides this with the --user flag or "cli".
        timeout:        Per-request timeout in seconds (min 1).
                        Overrides client default for this call only.

        Returns ScanResult. BLOCK is not an exception - check result.decision.

        Spec: Section 4, Section 8 (WrapSecBlockError not raised automatically)
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
        if model:
            body["model"] = model

        data = self._request(method="POST", path="/ai/request", timeout=t, json=body)
        return ScanResult.from_dict(data)

    def get_request(self, trace_id: str, timeout: int | None = None) -> dict[str, Any]:
        """
        Retrieve the full audit record for a single request by trace ID.
        Includes proxy enrichment data when execution_mode is "proxy".
        Scoped to the caller's dept/tenant - 404 if out of scope.

        Returns a raw dict (structure varies by execution_mode).
        """
        return self._request(
            "GET", f"/ai/requests/{trace_id}",
            self._resolve_timeout(timeout),
        )

    def audit_export(
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
            data = client.audit_export()
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

        t    = self._resolve_timeout(timeout)
        url  = self._url("/audit/export")
        resp = requests.get(
            url,
            headers = build_headers(api_key),
            params  = params,
            timeout = t,
        )
        if resp.ok:
            return resp.content
        response_data = None
        try:
            response_data = resp.json()
        except Exception:
            pass
        raise map_response_error(resp.status_code, response_data)

    def batch(
        self,
        texts:     list[str],
        mode:      str = "fast",
        user:      str = "sdk",
        timeout:   int | None = None,
        delay_ms:  int = 0,
    ) -> list[ScanResult]:
        """
        Scan multiple inputs. Returns results in the same order as inputs.

        texts:    List of prompts to scan.
        delay_ms: Milliseconds to wait between requests (default 0).
                  Use 100ms for large batches to avoid rate limiting.
        timeout:  Per-request timeout (not total batch time).

        Spec: Section 13.1 (batch command)
        """
        results: list[ScanResult] = []
        for i, text in enumerate(texts):
            if delay_ms > 0 and i > 0:
                time.sleep(delay_ms / 1000)
            results.append(self.scan(text, mode=mode, user=user, timeout=timeout))
        return results

    def audit_list(
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
        """
        List recent audit log entries. Read-only.
        Scope is bounded by the API key used.

        Spec: Section 13.2 (wrapsec audit list)
        """
        params: dict[str, str] = {"limit": str(min(limit, 100)), "offset": str(max(offset, 0))}
        if decision:        params["decision"]        = decision
        if reason:          params["primary_reason"]  = reason
        if execution_mode:  params["execution_mode"]  = execution_mode
        if from_date:       params["from"]            = from_date
        if to_date:         params["to"]              = to_date

        data = self._request("GET", "/audit/logs", self._resolve_timeout(timeout), params=params)
        return [AuditLog.from_dict(item) for item in data.get("items", data.get("logs", []))]

    def audit_get(self, trace_id: str, timeout: int | None = None) -> AuditLog:
        """
        Retrieve a single audit log entry by trace ID. Read-only.
        Uses the list endpoint with trace_id filter - no dedicated detail endpoint.

        Spec: Section 13.2 (wrapsec audit get)
        """
        data  = self._request(
            "GET", "/audit/logs",
            self._resolve_timeout(timeout),
            params={"trace_id": trace_id, "limit": "1"},
        )
        items = data.get("items", data.get("logs", []))
        if not items:
            raise WrapSecError(f"Audit record not found: {trace_id}")
        return AuditLog.from_dict(items[0])

    def audit_stats(
        self,
        from_date: str | None = None,
        to_date:   str | None = None,
        timeout:   int | None = None,
    ) -> AuditStats:
        """
        Retrieve aggregated audit statistics. Read-only.

        Spec: Section 13.2 (wrapsec audit stats)
        """
        params: dict[str, str] = {}
        if from_date: params["from"] = from_date
        if to_date:   params["to"]   = to_date

        data = self._request("GET", "/audit/stats", self._resolve_timeout(timeout), params=params)
        return AuditStats.from_dict(data)

    def settings_get(self, timeout: int | None = None) -> dict[str, Any]:
        """
        Retrieve active gateway configuration. Read-only.
        Returns raw dict - no model wrapping (structure varies by config source).

        Spec: Section 13.2 (wrapsec settings get)
        """
        thresholds  = self._request("GET", "/settings/thresholds",  self._resolve_timeout(timeout))
        layers      = self._request("GET", "/settings/layers",      self._resolve_timeout(timeout))
        llm         = self._request("GET", "/settings/llm",         self._resolve_timeout(timeout))
        rate_limit  = self._request("GET", "/settings/rate_limit",  self._resolve_timeout(timeout))
        return {
            "thresholds":  thresholds,
            "layers":      layers,
            "llm":         llm,
            "rate_limit":  rate_limit,
        }

    def keys_list(self, timeout: int | None = None) -> list[dict[str, Any]]:
        """
        List API keys visible to the current key. Read-only.
        Does NOT return key secrets - never retrievable after creation.

        Spec: Section 13.2 (wrapsec keys list)
        """
        data = self._request("GET", "/keys", self._resolve_timeout(timeout))
        return data.get("keys", [])

    def health_live(self, timeout: int = 5) -> bool:
        """
        Check if the API is reachable (/health/live). No auth required.
        Used by ping command.

        Fixed timeout: 5s (not user configurable per spec Section 13.2)
        Spec: Section 13.2 (wrapsec ping)
        """
        try:
            resp = requests.get(
                f"{self._base_url}/health/live",
                timeout=timeout,
            )
            return resp.ok
        except Exception:
            return False

    def health_ready(self, timeout: int = 5) -> dict[str, Any]:
        """
        Check full service health (/health/ready). Auth required.
        Used by doctor command.

        Spec: Section 13.2 (wrapsec doctor)
        """
        api_key = self._require_api_key()
        resp = requests.get(
            f"{self._base_url}/health/ready",
            headers=build_headers(api_key),
            timeout=timeout,
        )
        if resp.ok:
            return resp.json()
        response_data = None
        try:
            response_data = resp.json()
        except Exception:
            pass
        raise map_response_error(resp.status_code, response_data)

    def health_config(self, timeout: int = 5) -> dict[str, Any]:
        """
        Retrieve gateway active config for version check in doctor.
        """
        api_key = self._require_api_key()
        resp = requests.get(
            f"{self._base_url}/health/config",
            headers=build_headers(api_key),
            timeout=timeout,
        )
        if resp.ok:
            return resp.json()
        return {}
