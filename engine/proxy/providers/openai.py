"""
OpenAI-compatible provider for proxy mode.

Handles any endpoint that speaks the OpenAI chat completions API:
  - OpenAI            https://api.openai.com/v1
  - Azure OpenAI      https://your-resource.openai.azure.com/openai
  - Groq              https://api.groq.com/openai/v1
  - Together AI       https://api.together.xyz/v1
  - Anyscale          https://api.endpoints.anyscale.com/v1
  - Any local server  that implements the OpenAI chat completions format

No additional code is needed for new compatible providers -- just
configure a different base_url in the dashboard.
"""

import logging
import time

import httpx

from engine.proxy.providers.base import BaseProxyProvider, ProviderResponse

logger = logging.getLogger("wrapsec.proxy.openai")


class OpenAIProxyProvider(BaseProxyProvider):

    def __init__(self, api_key: str, base_url: str, timeout: int):
        self.api_key  = api_key
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
        Forward a chat completions request to an OpenAI-compatible endpoint.
        Passes through all kwargs (temperature, max_tokens, top_p, etc.) unchanged.
        WrapSec does not modify any model parameters.
        """
        start = time.monotonic()

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
        }

        # Forward trace ID for distributed tracing and provider-side correlation
        if trace_id:
            headers["X-WrapSec-Trace-Id"] = trace_id

        payload = {
            "model":    model,
            "messages": messages,
            **kwargs,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()

        data       = resp.json()
        latency_ms = int((time.monotonic() - start) * 1000)

        content       = data["choices"][0]["message"]["content"]
        finish_reason = data["choices"][0].get("finish_reason", "stop")
        model_used    = data.get("model", model)

        logger.debug(
            f"OpenAI provider responded -- model={model_used} "
            f"latency={latency_ms}ms finish_reason={finish_reason}"
        )

        return ProviderResponse(
            content       = content,
            model         = model_used,
            finish_reason = finish_reason,
            latency_ms    = latency_ms,
            raw           = data,
        )