# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests — provider layer and extended OutputGuard.

Run:
    $env:TESTING = "true"
    pytest tests/unit/test_proxy_provider_layer.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx


# ===========================================================================
# Model string parser tests
# ===========================================================================

class TestParseModelString:

    def test_valid_openai(self):
        from engine.proxy.router import parse_model_string
        provider, model = parse_model_string("openai/gpt-4o")
        assert provider == "openai"
        assert model    == "gpt-4o"

    def test_valid_ollama(self):
        from engine.proxy.router import parse_model_string
        provider, model = parse_model_string("ollama/llama3.2")
        assert provider == "ollama"
        assert model    == "llama3.2"

    def test_valid_custom(self):
        from engine.proxy.router import parse_model_string
        provider, model = parse_model_string("custom/my-model")
        assert provider == "custom"
        assert model    == "my-model"

    def test_model_with_version(self):
        from engine.proxy.router import parse_model_string
        provider, model = parse_model_string("openai/gpt-4o-mini")
        assert provider == "openai"
        assert model    == "gpt-4o-mini"

    def test_no_slash_raises(self):
        from engine.proxy.router import parse_model_string
        with pytest.raises(ValueError, match="provider/model format"):
            parse_model_string("gpt-4o")

    def test_empty_string_raises(self):
        from engine.proxy.router import parse_model_string
        with pytest.raises(ValueError):
            parse_model_string("")

    def test_empty_provider_raises(self):
        from engine.proxy.router import parse_model_string
        with pytest.raises(ValueError, match="Provider name is empty"):
            parse_model_string("/gpt-4o")

    def test_empty_model_raises(self):
        from engine.proxy.router import parse_model_string
        with pytest.raises(ValueError, match="Model name is empty"):
            parse_model_string("openai/")

    def test_unsupported_provider_raises(self):
        from engine.proxy.router import parse_model_string
        with pytest.raises(ValueError, match="Unsupported provider"):
            parse_model_string("anthropic/claude-3")

    def test_only_slash_raises(self):
        from engine.proxy.router import parse_model_string
        with pytest.raises(ValueError):
            parse_model_string("/")


# ===========================================================================
# OpenAI provider tests
# ===========================================================================

class TestOpenAIProxyProvider:

    def _make_provider(self):
        from engine.proxy.providers.openai import OpenAIProxyProvider
        return OpenAIProxyProvider(
            api_key  = "sk-test-key",
            base_url = "https://api.openai.com/v1",
            timeout  = 30,
        )

    def _mock_openai_response(self, content="Hello world", model="gpt-4o"):
        return {
            "choices": [
                {
                    "message":       {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                    "index":         0,
                }
            ],
            "model": model,
        }

    @pytest.mark.asyncio
    async def test_forward_request_returns_provider_response(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "What is 2+2?"}]

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_openai_response("4")
        mock_resp.raise_for_status  = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            result = await provider.chat_completions(
                model="gpt-4o", messages=messages
            )

        assert result.content       == "4"
        assert result.model         == "gpt-4o"
        assert result.finish_reason == "stop"
        assert result.latency_ms    >= 0
        assert result.raw           is not None

    @pytest.mark.asyncio
    async def test_authorization_header_set(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]
        captured_headers = {}

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_openai_response()
        mock_resp.raise_for_status  = MagicMock()

        async def fake_post(url, headers=None, json=None, **kwargs):
            captured_headers.update(headers or {})
            return mock_resp

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = fake_post
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            await provider.chat_completions(model="gpt-4o", messages=messages)

        assert captured_headers.get("Authorization") == "Bearer sk-test-key"

    @pytest.mark.asyncio
    async def test_trace_id_forwarded(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]
        captured_headers = {}

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_openai_response()
        mock_resp.raise_for_status  = MagicMock()

        async def fake_post(url, headers=None, json=None, **kwargs):
            captured_headers.update(headers or {})
            return mock_resp

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = fake_post
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            await provider.chat_completions(
                model="gpt-4o", messages=messages, trace_id="req_01test"
            )

        assert captured_headers.get("X-WrapSec-Trace-Id") == "req_01test"

    @pytest.mark.asyncio
    async def test_kwargs_passed_to_provider(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]
        captured_payload = {}

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_openai_response()
        mock_resp.raise_for_status  = MagicMock()

        async def fake_post(url, headers=None, json=None, **kwargs):
            captured_payload.update(json or {})
            return mock_resp

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = fake_post
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            await provider.chat_completions(
                model="gpt-4o", messages=messages,
                temperature=0.5, max_tokens=100
            )

        assert captured_payload.get("temperature") == 0.5
        assert captured_payload.get("max_tokens")  == 100

    @pytest.mark.asyncio
    async def test_timeout_propagates(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=httpx.TimeoutException("timed out")
            )
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            with pytest.raises(httpx.TimeoutException):
                await provider.chat_completions(model="gpt-4o", messages=messages)

    @pytest.mark.asyncio
    async def test_http_error_propagates(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "401", request=MagicMock(), response=MagicMock(status_code=401)
            )
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            with pytest.raises(httpx.HTTPStatusError):
                await provider.chat_completions(model="gpt-4o", messages=messages)

    @pytest.mark.asyncio
    async def test_connect_error_propagates(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            with pytest.raises(httpx.ConnectError):
                await provider.chat_completions(model="gpt-4o", messages=messages)


# ===========================================================================
# Ollama provider tests
# ===========================================================================

class TestOllamaProxyProvider:

    def _make_provider(self):
        from engine.proxy.providers.ollama import OllamaProxyProvider
        return OllamaProxyProvider(
            base_url = "http://localhost:11434",
            timeout  = 60,
        )

    @pytest.mark.asyncio
    async def test_translates_ollama_format_to_openai(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "What is 2+2?"}]

        ollama_response = {
            "message": {"role": "assistant", "content": "4"},
            "done":    True,
            "model":   "llama3.2",
        }

        mock_resp = MagicMock()
        mock_resp.json.return_value = ollama_response
        mock_resp.raise_for_status  = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            result = await provider.chat_completions(
                model="llama3.2", messages=messages
            )

        assert result.content       == "4"
        assert result.model         == "llama3.2"
        assert result.finish_reason == "stop"
        assert result.latency_ms    >= 0

    @pytest.mark.asyncio
    async def test_uses_api_chat_endpoint(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]
        captured_url = {}

        ollama_response = {
            "message": {"role": "assistant", "content": "Hi"},
            "done":    True,
        }

        mock_resp = MagicMock()
        mock_resp.json.return_value = ollama_response
        mock_resp.raise_for_status  = MagicMock()

        async def fake_post(url, **kwargs):
            captured_url["url"] = url
            return mock_resp

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = fake_post
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            await provider.chat_completions(model="llama3.2", messages=messages)

        assert captured_url["url"] == "http://localhost:11434/api/chat"

    @pytest.mark.asyncio
    async def test_stream_false_in_payload(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]
        captured_payload = {}

        ollama_response = {
            "message": {"role": "assistant", "content": "Hi"},
            "done":    True,
        }

        mock_resp = MagicMock()
        mock_resp.json.return_value = ollama_response
        mock_resp.raise_for_status  = MagicMock()

        async def fake_post(url, headers=None, json=None, **kwargs):
            captured_payload.update(json or {})
            return mock_resp

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = fake_post
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            await provider.chat_completions(model="llama3.2", messages=messages)

        assert captured_payload.get("stream") is False

    @pytest.mark.asyncio
    async def test_timeout_propagates(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=httpx.TimeoutException("timed out")
            )
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            with pytest.raises(httpx.TimeoutException):
                await provider.chat_completions(model="llama3.2", messages=messages)

    @pytest.mark.asyncio
    async def test_connect_error_propagates(self):
        provider = self._make_provider()
        messages = [{"role": "user", "content": "Hello"}]

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client      = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            with pytest.raises(httpx.ConnectError):
                await provider.chat_completions(model="llama3.2", messages=messages)


# ===========================================================================
# OutputGuard decision layer tests
# ===========================================================================

class TestOutputGuardDecision:

    def _make_guard(self):
        from engine.guardrails.output_guard import OutputGuard
        return OutputGuard()

    def test_allow_clean_text(self):
        guard  = self._make_guard()
        result = guard.inspect("The capital of France is Paris.")
        assert result.decision       == "ALLOW"
        assert result.primary_reason == "NO_THREAT_DETECTED"
        assert result.was_sanitized  is False
        assert result.sanitized_text is None

    def test_allow_empty_text(self):
        guard  = self._make_guard()
        result = guard.inspect("")
        assert result.decision == "ALLOW"

    def test_sanitize_on_pii_detected(self):
        guard  = self._make_guard()
        result = guard.inspect(
            "Your account email is john.doe@example.com and we will contact you."
        )
        # PII detected -- must be SANITIZE or BLOCK, never ALLOW
        assert result.decision in ("SANITIZE", "BLOCK")
        if result.decision == "SANITIZE":
            assert result.was_sanitized  is True
            assert result.sanitized_text is not None
            assert result.primary_reason == "PII_GUARDRAIL_SANITIZE"

    def test_sanitize_preserves_non_pii_content(self):
        guard  = self._make_guard()
        result = guard.inspect(
            "Hello! Your SSN 123-45-6789 has been noted. Have a great day!"
        )
        if result.decision == "SANITIZE":
            assert "Have a great day" in result.sanitized_text

    def test_existing_fields_still_present(self):
        """Verify backward compatibility -- existing callers must not break."""
        guard  = self._make_guard()
        result = guard.inspect("Plain clean text.")
        # All original fields must still exist
        assert hasattr(result, "text")
        assert hasattr(result, "sanitized_text")
        assert hasattr(result, "was_sanitized")
        assert hasattr(result, "redacted_types")
        # New fields must also exist
        assert hasattr(result, "decision")
        assert hasattr(result, "primary_reason")
        assert hasattr(result, "pii_score")
        assert hasattr(result, "threats")
        assert hasattr(result, "confidence")

    def test_decision_values_are_valid(self):
        guard  = self._make_guard()
        result = guard.inspect("Some text to check.")
        assert result.decision in ("ALLOW", "BLOCK", "SANITIZE")

    def test_system_error_returns_block(self):
        """If OutputGuard itself fails, it must fail closed (BLOCK)."""
        from engine.guardrails.output_guard import OutputGuard

        guard = OutputGuard()

        with patch.object(guard._detector, "detect", side_effect=RuntimeError("detector crashed")):
            result = guard.inspect("Some text")

        assert result.decision       == "BLOCK"
        assert result.primary_reason == "SYSTEM_ERROR"
        assert result.confidence     == 0.0
        assert result.was_sanitized  is False