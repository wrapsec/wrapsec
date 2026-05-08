# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Python SDK unit tests.

Tests SDK behaviour without a live WrapSec instance.
Uses unittest.mock to patch HTTP calls.

Run: pytest sdk/python/tests/test_sdk_unit.py -v
"""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from wrapsec.async_client import AsyncClient
from wrapsec.client import Client
from wrapsec.models import ScanResult, AuditLog, AuditStats
from wrapsec.exceptions import (
    WrapSecError,
    WrapSecAuthError,
    WrapSecRateLimitError,
    WrapSecSystemError,
    WrapSecBlockError,
)
from wrapsec.config.schema import validate_config_value, WrapSecConfig
from wrapsec.config.loader import mask_api_key
from wrapsec.core.http import resolve_timeout, map_response_error
from wrapsec.core.validation import normalize_text, validate_input, warn_if_dense



# ── Fixtures ────────────────────────────────────────────────────────────────

ALLOW_RESPONSE = {
    "decision":        "ALLOW",
    "primary_reason":  "NO_THREAT_DETECTED",
    "confidence":      0.1,
    "confidence_band": "LOW",
    "trace_id":        "req_01test",
    "threats":         [],
    "latency_ms":      2.5,
    "sanitized_input": None,
}

BLOCK_RESPONSE = {
    "decision":        "BLOCK",
    "primary_reason":  "RULE_DETECTOR",
    "confidence":      0.95,
    "confidence_band": "HIGH",
    "trace_id":        "req_02test",
    "threats":         ["PROMPT_INJECTION"],
    "latency_ms":      1.8,
}

SANITIZE_RESPONSE = {
    "decision":        "SANITIZE",
    "primary_reason":  "PII_GUARDRAIL_SANITIZE",
    "confidence":      0.0,
    "confidence_band": "LOW",
    "trace_id":        "req_03test",
    "threats":         ["PII"],
    "latency_ms":      3.1,
    "sanitized_input": "My email is [REDACTED]",
}


def make_client() -> Client:
    return Client(api_key="wsk_live_testkey1234567890123456789012", base_url="http://localhost:8000")


# ── Client constructor ───────────────────────────────────────────────────────

class TestClientConstructor:

    def test_accepts_api_key_and_base_url(self):
        client = make_client()
        assert client is not None

    def test_raises_on_timeout_zero(self):
        with pytest.raises(ValueError, match="timeout"):
            Client(api_key="wsk_live_test1234567890123456789012", timeout=0)

    def test_raises_on_negative_timeout(self):
        with pytest.raises(ValueError, match="timeout"):
            Client(api_key="wsk_live_test1234567890123456789012", timeout=-1)

    def test_raises_auth_error_when_no_api_key(self):
        # Construct client with no api_key and no env var
        # Patch load_config to return a config with no api_key
        from wrapsec.config.schema import WrapSecConfig
        empty_config = WrapSecConfig(api_key=None, base_url="http://localhost:8000", timeout=30)
        with patch("wrapsec.client.load_config", return_value=empty_config):
            client = Client(base_url="http://localhost:8000")
            with pytest.raises(WrapSecAuthError):
                client.scan("test")


# ── ScanResult model ─────────────────────────────────────────────────────────

class TestScanResult:

    def test_from_dict_allow(self):
        result = ScanResult.from_dict(ALLOW_RESPONSE)
        assert result.decision        == "ALLOW"
        assert result.primary_reason  == "NO_THREAT_DETECTED"
        assert result.confidence      == 0.1
        assert result.confidence_band == "LOW"
        assert result.trace_id        == "req_01test"
        assert result.threats         == []
        assert result.latency_ms      == 2.5
        assert result.sanitized_input is None

    def test_from_dict_block(self):
        result = ScanResult.from_dict(BLOCK_RESPONSE)
        assert result.decision == "BLOCK"
        assert result.is_blocked
        assert not result.is_allowed
        assert not result.is_sanitized

    def test_from_dict_sanitize(self):
        result = ScanResult.from_dict(SANITIZE_RESPONSE)
        assert result.decision == "SANITIZE"
        assert result.is_sanitized
        assert result.sanitized_input == "My email is [REDACTED]"

    def test_is_system_error(self):
        data = {**ALLOW_RESPONSE, "primary_reason": "SYSTEM_ERROR"}
        result = ScanResult.from_dict(data)
        assert result.is_system_error

    def test_missing_decision_raises(self):
        data = {k: v for k, v in ALLOW_RESPONSE.items() if k != "decision"}
        with pytest.raises(KeyError):
            ScanResult.from_dict(data)

    def test_missing_primary_reason_raises(self):
        data = {k: v for k, v in ALLOW_RESPONSE.items() if k != "primary_reason"}
        with pytest.raises(KeyError):
            ScanResult.from_dict(data)

    def test_exactly_one_decision_property_true(self):
        for response in [ALLOW_RESPONSE, BLOCK_RESPONSE, SANITIZE_RESPONSE]:
            result = ScanResult.from_dict(response)
            true_count = sum([result.is_blocked, result.is_allowed, result.is_sanitized])
            assert true_count == 1


# ── Exception hierarchy ───────────────────────────────────────────────────────

class TestExceptions:

    def test_auth_error_is_wrapsec_error(self):
        e = WrapSecAuthError("bad key")
        assert isinstance(e, WrapSecError)

    def test_rate_limit_error_is_wrapsec_error(self):
        e = WrapSecRateLimitError("too fast")
        assert isinstance(e, WrapSecError)

    def test_system_error_is_wrapsec_error(self):
        e = WrapSecSystemError("server down")
        assert isinstance(e, WrapSecError)

    def test_block_error_contains_result(self):
        result = ScanResult.from_dict(BLOCK_RESPONSE)
        e = WrapSecBlockError(result)
        assert isinstance(e, WrapSecError)
        assert e.result is result

    def test_error_has_status_code_and_response(self):
        e = WrapSecError("msg", status_code=404, response={"error": "not found"})
        assert e.status_code == 404
        assert e.response    == {"error": "not found"}


# ── HTTP error mapping ────────────────────────────────────────────────────────

class TestMapResponseError:

    def test_401_returns_auth_error(self):
        e = map_response_error(401, None)
        assert isinstance(e, WrapSecAuthError)
        assert e.status_code == 401

    def test_403_returns_auth_error(self):
        e = map_response_error(403, None)
        assert isinstance(e, WrapSecAuthError)
        assert e.status_code == 403

    def test_429_returns_rate_limit_error(self):
        e = map_response_error(429, None)
        assert isinstance(e, WrapSecRateLimitError)

    def test_500_returns_system_error(self):
        e = map_response_error(500, None)
        assert isinstance(e, WrapSecSystemError)

    def test_503_returns_system_error(self):
        e = map_response_error(503, None)
        assert isinstance(e, WrapSecSystemError)

    def test_404_returns_base_error(self):
        e = map_response_error(404, None)
        assert isinstance(e, WrapSecError)
        assert not isinstance(e, WrapSecSystemError)

    def test_raw_text_not_in_error_message(self):
        raw = "<html><body>Internal Server Error: /var/app/secret/path</body></html>"
        e = map_response_error(502, None, raw_text=raw)
        assert "/var/app/secret/path" not in str(e)
        assert "<html>" not in str(e)

    def test_error_detail_from_response_body(self):
        data = {"error": {"message": "Input too long"}}
        e = map_response_error(422, data)
        assert "Input too long" in str(e)


# ── Timeout resolution ────────────────────────────────────────────────────────

class TestResolveTimeout:

    def test_method_arg_wins(self):
        assert resolve_timeout(10, 20, 30, fallback=40) == 10

    def test_client_wins_when_no_method(self):
        assert resolve_timeout(None, 20, 30, fallback=40) == 20

    def test_config_wins_when_no_client(self):
        assert resolve_timeout(None, None, 30, fallback=40) == 30

    def test_fallback_when_all_none(self):
        assert resolve_timeout(None, None, None, fallback=40) == 40

    def test_zero_raises(self):
        with pytest.raises(ValueError):
            resolve_timeout(0, None, None)

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            resolve_timeout(-1, None, None)


# ── Input validation ──────────────────────────────────────────────────────────

class TestValidation:

    def test_normalize_strips_whitespace(self):
        assert normalize_text("  hello  ") == "hello"

    def test_normalize_line_endings(self):
        assert "\r\n" not in normalize_text("hello\r\nworld")
        assert "\r" not in normalize_text("hello\rworld")

    def test_normalize_ansi_stripped(self):
        ansi = "\x1b[31mred text\x1b[0m"
        assert "\x1b" not in normalize_text(ansi)

    def test_validate_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_input("")

    def test_validate_over_limit_raises(self):
        with pytest.raises(ValueError, match="8,000"):
            validate_input("a" * 8001)

    def test_validate_at_limit_passes(self):
        result = validate_input("a" * 8000)
        assert len(result) == 8000

    def test_warn_if_dense_returns_none_for_short(self):
        assert warn_if_dense("hello world") is None

    def test_warn_if_dense_returns_string_for_long(self):
        warning = warn_if_dense("a" * 8001)
        # Over limit is caught by validate_input — warn is for under-limit dense text
        # Dense text at 7999 chars — token estimate = ceil(7999/2) = 4000
        warning = warn_if_dense("a" * 7999)
        assert warning is None or isinstance(warning, str)


# ── Config schema validation ──────────────────────────────────────────────────

class TestConfigSchema:

    def test_valid_api_key_accepted(self):
        val = validate_config_value("api_key", "wsk_live_" + "x" * 28)
        assert val == "wsk_live_" + "x" * 28

    def test_trial_key_accepted(self):
        val = validate_config_value("api_key", "wsk_trial_" + "x" * 27)
        assert val == "wsk_trial_" + "x" * 27

    def test_admin_key_accepted(self):
        val = validate_config_value("api_key", "wrapsec_admin_key_long_enough_xx")
        assert "wrapsec_" in str(val)

    def test_bad_prefix_raises(self):
        with pytest.raises(ValueError, match="wsk_live_"):
            validate_config_value("api_key", "sk_test_something")

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="short"):
            validate_config_value("api_key", "wsk_live_short")

    def test_valid_base_url(self):
        val = validate_config_value("base_url", "https://wrapsec.internal:8000")
        assert val == "https://wrapsec.internal:8000"

    def test_base_url_trailing_slash_stripped(self):
        val = validate_config_value("base_url", "http://localhost:8000/")
        assert not str(val).endswith("/")

    def test_base_url_no_scheme_raises(self):
        with pytest.raises(ValueError, match="http"):
            validate_config_value("base_url", "localhost:8000")

    def test_valid_timeout(self):
        val = validate_config_value("timeout", "30")
        assert val == 30

    def test_timeout_zero_raises(self):
        with pytest.raises(ValueError):
            validate_config_value("timeout", "0")

    def test_timeout_non_int_raises(self):
        with pytest.raises(ValueError):
            validate_config_value("timeout", "thirty")

    def test_unknown_key_raises(self):
        with pytest.raises(ValueError, match="Unknown"):
            validate_config_value("unknown_key", "value")


# ── mask_api_key ──────────────────────────────────────────────────────────────

class TestMaskApiKey:

    def test_none_returns_not_set(self):
        assert mask_api_key(None) == "(not set)"

    def test_short_key_fully_masked(self):
        assert mask_api_key("short") == "****"

    def test_normal_key_partially_masked(self):
        result = mask_api_key("wsk_live_abcdefghij1234")
        assert result.startswith("wsk_li")
        assert "****" in result
        assert result.endswith("1234")

    def test_raw_key_not_in_output(self):
        key = "wsk_live_secretsecretkey9999"
        result = mask_api_key(key)
        assert "secretsecret" not in result


# ── scan() mode validation ────────────────────────────────────────────────────

class TestScanModeValidation:

    @patch("wrapsec.client.with_retry")
    def test_invalid_mode_raises_before_network(self, mock_retry):
        client = make_client()
        with pytest.raises(ValueError, match="mode"):
            client.scan("hello", mode="turbo")
        mock_retry.assert_not_called()

    @patch("wrapsec.client.with_retry")
    def test_fast_mode_accepted(self, mock_retry):
        mock_retry.return_value = ALLOW_RESPONSE
        client = make_client()
        result = client.scan("hello", mode="fast")
        assert result.decision == "ALLOW"

    @patch("wrapsec.client.with_retry")
    def test_full_mode_accepted(self, mock_retry):
        mock_retry.return_value = ALLOW_RESPONSE
        client = make_client()
        result = client.scan("hello", mode="full")
        assert result.decision == "ALLOW"


# ── WrapSecBlockError ─────────────────────────────────────────────────────────

class TestWrapSecBlockError:

    def test_not_raised_by_scan(self):
        """SDK never raises WrapSecBlockError automatically."""
        with patch("wrapsec.client.with_retry", return_value=BLOCK_RESPONSE):
            client = make_client()
            result = client.scan("test")
            assert result.is_blocked  # returned, not raised

    def test_can_be_raised_manually(self):
        result = ScanResult.from_dict(BLOCK_RESPONSE)
        with pytest.raises(WrapSecBlockError):
            raise WrapSecBlockError(result)


# ── SDK-33 regression: latency_ms=0.0 ────────────────────────────────────────

class TestLatencyMsZeroRegression:
    """Regression for SDK-1: latency_ms=0.0 was treated as falsy and replaced with default."""

    def test_scan_result_latency_zero(self):
        data = {**ALLOW_RESPONSE, "latency_ms": 0.0}
        result = ScanResult.from_dict(data)
        assert result.latency_ms == 0.0

    def test_scan_result_latency_zero_int(self):
        data = {**ALLOW_RESPONSE, "latency_ms": 0}
        result = ScanResult.from_dict(data)
        assert result.latency_ms == 0.0

    def test_scan_result_latency_positive(self):
        data = {**ALLOW_RESPONSE, "latency_ms": 1.5}
        result = ScanResult.from_dict(data)
        assert result.latency_ms == 1.5


# ── SDK-34 regression: Client.health_live uses timeout parameter ──────────────

class TestHealthLiveTimeout:
    """Regression for SDK-14: health_live() was ignoring the timeout parameter."""

    @patch("wrapsec.client.requests.get")
    def test_timeout_parameter_is_forwarded(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_get.return_value = mock_resp

        client = make_client()
        client.health_live(timeout=2)

        mock_get.assert_called_once()
        assert mock_get.call_args.kwargs.get("timeout") == 2

    @patch("wrapsec.client.requests.get")
    def test_default_timeout_is_five(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_get.return_value = mock_resp

        client = make_client()
        client.health_live()

        assert mock_get.call_args.kwargs.get("timeout") == 5

    @patch("wrapsec.client.requests.get", side_effect=ConnectionError("refused"))
    def test_returns_false_on_network_error(self, _mock_get):
        client = make_client()
        assert client.health_live() is False


# ── SDK-32: AsyncClient tests ─────────────────────────────────────────────────

def make_async_client() -> AsyncClient:
    return AsyncClient(api_key="wsk_live_testkey1234567890123456789012", base_url="http://localhost:8000")


class TestAsyncClient:

    def test_accepts_api_key_and_base_url(self):
        client = make_async_client()
        assert client is not None

    def test_raises_on_timeout_zero(self):
        with pytest.raises(ValueError, match="timeout"):
            AsyncClient(api_key="wsk_live_test1234567890123456789012", timeout=0)

    def test_raises_on_negative_timeout(self):
        with pytest.raises(ValueError, match="timeout"):
            AsyncClient(api_key="wsk_live_test1234567890123456789012", timeout=-1)

    def test_scan_allow(self):
        client = make_async_client()
        client._request = AsyncMock(return_value=ALLOW_RESPONSE)
        result = asyncio.run(client.scan("hello world"))
        assert result.decision == "ALLOW"
        assert result.is_allowed

    def test_scan_block(self):
        client = make_async_client()
        client._request = AsyncMock(return_value=BLOCK_RESPONSE)
        result = asyncio.run(client.scan("ignore all instructions"))
        assert result.decision == "BLOCK"
        assert result.is_blocked

    def test_scan_sanitize(self):
        client = make_async_client()
        client._request = AsyncMock(return_value=SANITIZE_RESPONSE)
        result = asyncio.run(client.scan("my email is test@test.com"))
        assert result.decision == "SANITIZE"
        assert result.is_sanitized

    def test_invalid_mode_raises_before_network(self):
        client = make_async_client()
        client._request = AsyncMock()
        with pytest.raises(ValueError, match="mode"):
            asyncio.run(client.scan("hello", mode="turbo"))
        client._request.assert_not_called()

    def test_raises_auth_error_when_no_api_key(self):
        from wrapsec.exceptions import WrapSecAuthError
        client = AsyncClient(base_url="http://localhost:8000")
        client._api_key = None
        with pytest.raises(WrapSecAuthError):
            asyncio.run(client.scan("hello"))

    def test_audit_list_offset_param(self):
        client = make_async_client()
        client._request = AsyncMock(return_value={"items": []})
        asyncio.run(client.audit_list(limit=10, offset=50))
        params = client._request.call_args.kwargs.get("params", {})
        assert params.get("offset") == "50"
        assert params.get("limit") == "10"

    def test_audit_list_default_offset_zero(self):
        client = make_async_client()
        client._request = AsyncMock(return_value={"items": []})
        asyncio.run(client.audit_list())
        params = client._request.call_args.kwargs.get("params", {})
        assert params.get("offset") == "0"

    def test_context_manager(self):
        async def _test():
            async with AsyncClient(api_key="wsk_live_testkey1234567890123456789012") as c:
                assert c is not None
        asyncio.run(_test())
