# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import time
import logging
import httpx
from interfaces.base_llm import BaseLLMClient, LLMResponse
from config.settings import get_settings

logger = logging.getLogger("wrapsec.clients")


class OpenAIClient(BaseLLMClient):
    """OpenAI-compatible client. Handles openai, custom, and any OpenAI-compatible endpoint."""

    def __init__(self, llm_settings: dict | None = None):
        self._llm_settings = llm_settings or {}

    @property
    def provider(self) -> str:
        return self._llm_settings.get("provider") or "openai"

    def _resolve_api_key(self) -> str:
        # DB-stored key takes precedence over env var
        return self._llm_settings.get("api_key") or get_settings().openai_api_key

    def _resolve_base_url(self) -> str:
        return (
            self._llm_settings.get("base_url")
            or get_settings().llm_base_url
            or "https://api.openai.com/v1"
        )

    async def complete(
        self,
        system_prompt: str,
        user_prompt:   str,
        model:         str | None = None,
        temperature:   float = 0.0,
        max_tokens:    int = 500,
    ) -> LLMResponse:
        _settings      = get_settings()
        start          = time.perf_counter()
        resolved_model = model or self._llm_settings.get("model") or _settings.llm_model
        timeout        = self._llm_settings.get("timeout") or _settings.llm_timeout
        base_url       = self._resolve_base_url()
        api_key        = self._resolve_api_key()

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type":  "application/json",
                    },
                    json={
                        "model":       resolved_model,
                        "temperature": temperature,
                        "max_tokens":  max_tokens,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user",   "content": user_prompt},
                        ],
                    },
                )
                response.raise_for_status()
                data = response.json()

                return LLMResponse(
                    content           = data["choices"][0]["message"]["content"],
                    model             = data.get("model", resolved_model),
                    provider          = self.provider,
                    prompt_tokens     = data.get("usage", {}).get("prompt_tokens", 0),
                    completion_tokens = data.get("usage", {}).get("completion_tokens", 0),
                    latency_ms        = (time.perf_counter() - start) * 1000,
                )

        except Exception as e:
            logger.error(f"OpenAI-compatible completion failed ({base_url}): {e}")
            return LLMResponse(
                content    = "",
                model      = resolved_model,
                provider   = self.provider,
                latency_ms = (time.perf_counter() - start) * 1000,
            )

    async def is_available(self) -> bool:
        base_url = self._resolve_base_url()
        api_key  = self._resolve_api_key()
        if not api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(
                    f"{base_url}/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                return response.status_code == 200
        except Exception:
            return False