import time
import logging
import httpx
from interfaces.base_llm import BaseLLMClient, LLMResponse
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.clients")
settings = get_settings()


class LocalLLMClient(BaseLLMClient):
    """
    Ollama local LLM client.
    Uses the Ollama /api/chat endpoint.
    """

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
        start         = time.perf_counter()
        resolved_model = model or settings.llm_model

        try:
            async with httpx.AsyncClient(timeout=settings.llm_timeout) as client:
                response = await client.post(
                    f"{settings.llm_base_url}/api/chat",
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
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{settings.llm_base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False