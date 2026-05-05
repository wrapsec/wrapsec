# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Ollama provider for proxy mode.

Ollama uses /api/chat instead of /v1/chat/completions and has a
different response format. This provider translates transparently
so the client never needs to know which backend is being used.

Ollama request:  POST /api/chat  { model, messages, stream: false }
Ollama response: { message: { role, content }, done: true, ... }

Translated to OpenAI format:
  { choices: [{ message: { role, content }, finish_reason: "stop" }], model }
"""

import logging
import time

import httpx

from engine.proxy.providers.base import BaseProxyProvider, ProviderResponse

logger = logging.getLogger("wrapsec.proxy.ollama")


class OllamaProxyProvider(BaseProxyProvider):

    def __init__(self, base_url: str, timeout: int):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout

    async def chat_completions(
        self,
        model:    str,
        messages: list[dict],
        trace_id: str | None = None,
        **kwargs,
    ) -> ProviderResponse:
        """
        Forward a chat request to Ollama and translate the response to
        OpenAI format. kwargs are not forwarded — Ollama has a different
        parameter structure. Full kwargs passthrough is planned.
        """
        start = time.monotonic()

        headers = {"Content-Type": "application/json"}
        if trace_id:
            headers["X-WrapSec-Trace-Id"] = trace_id

        payload = {
            "model":    model,
            "messages": messages,
            "stream":   False,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()

        data       = resp.json()
        latency_ms = int((time.monotonic() - start) * 1000)

        # Ollama response format: { "message": { "role": "assistant", "content": "..." } }
        content = data["message"]["content"]

        logger.debug(
            f"Ollama provider responded -- model={model} latency={latency_ms}ms"
        )

        return ProviderResponse(
            content       = content,
            model         = model,
            finish_reason = "stop",
            latency_ms    = latency_ms,
            raw           = data,
        )