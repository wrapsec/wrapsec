# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
import time

import httpx

from config.settings import get_settings
from interfaces.base_llm import BaseLLMClient, LLMResponse

logger = logging.getLogger("wrapsec.clients")


class LocalLLMClient(BaseLLMClient):

    def __init__(self, llm_settings: dict | None = None):
        self._llm_settings = llm_settings or {}

    @property
    def provider(self) -> str:
        return "ollama"

    async def complete(
        self,
        system_prompt: str,
        user_prompt:   str,
        model:         str | None = None,
        temperature:   float = 0.0,
        max_tokens:    int = 500,
    ) -> LLMResponse:
        start          = time.perf_counter()
        resolved_model = model or self._llm_settings.get("model") or get_settings().llm_model
        base_url       = self._llm_settings.get("base_url") or get_settings().llm_base_url
        timeout        = self._llm_settings.get("timeout")  or get_settings().llm_timeout

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{base_url}/api/chat",
                    json={
                        "model":  resolved_model,
                        "stream": False,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user",   "content": user_prompt},
                        ],
                    },
                )
                response.raise_for_status()
                data = response.json()

                return LLMResponse(
                    content           = data["message"]["content"],
                    model             = resolved_model,
                    provider          = self.provider,
                    prompt_tokens     = data.get("prompt_eval_count", 0),
                    completion_tokens = data.get("eval_count", 0),
                    latency_ms        = (time.perf_counter() - start) * 1000,
                )

        except Exception as e:
            logger.error(f"Ollama completion failed: {e}")
            return LLMResponse(
                content    = "",
                model      = resolved_model,
                provider   = self.provider,
                latency_ms = (time.perf_counter() - start) * 1000,
            )

    async def is_available(self) -> bool:
        timeout  = self._llm_settings.get("timeout") or get_settings().llm_timeout
        base_url = self._llm_settings.get("base_url") or get_settings().llm_base_url
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(f"{base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False