from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResponse:
    content:      str
    model:        str
    provider:     str
    prompt_tokens:    int = 0
    completion_tokens: int = 0
    latency_ms:   float = 0.0


class BaseLLMClient(ABC):
    """
    Abstract LLM client interface.
    All providers must implement this interface.
    Engine uses this — never calls providers directly.
    """

    @property
    @abstractmethod
    def provider(self) -> str:
        """Provider name — ollama | openai | groq"""

    @abstractmethod
    async def complete(
        self,
        system_prompt: str,
        user_prompt:   str,
        model:         str | None = None,
        temperature:   float = 0.0,
        max_tokens:    int = 500,
    ) -> LLMResponse:
        """
        Send a completion request to the LLM provider.
        Must never raise — return empty LLMResponse on failure.
        """

    @abstractmethod
    async def is_available(self) -> bool:
        """Health check — returns True if provider is reachable."""