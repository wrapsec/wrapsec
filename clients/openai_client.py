# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import time
import logging
import httpx
from interfaces.base_llm import BaseLLMClient, LLMResponse
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.clients")
settings = get_settings()

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIClient(BaseLLMClient):

    def __init__(self, llm_settings: dict | None = None):
        self._llm_settings = llm_settings or {}

    @property
    def provider(self) -> str:
        return "openai"

    async def complete(
        self,
        system_prompt: str,
        user_prompt:   str,
        model:         str | None = None,
        temperature:   float = 0.0,
        max_tokens:    int = 500,
    ) -> LLMResponse:
        start          = time.perf_counter()
        resolved_model = model or self._llm_settings.get("model") or settings.llm_model
        timeout        = self._llm_settings.get("timeout") or settings.llm_timeout

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    OPENAI_API_URL,
                    headers={
                        "Authorization": f"Bearer {settings.openai_api_key}",
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
            logger.error(f"OpenAI completion failed: {e}")
            return LLMResponse(
                content    = "",
                model      = resolved_model,
                provider   = self.provider,
                latency_ms = (time.perf_counter() - start) * 1000,
            )

    async def is_available(self) -> bool:
        if not settings.openai_api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {settings.openai_api_key}"},
                )
                return response.status_code == 200
        except Exception:
            return False