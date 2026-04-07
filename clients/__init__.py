from config.settings import get_settings
from interfaces.base_llm import BaseLLMClient

settings = get_settings()


def get_llm_client() -> BaseLLMClient:
    """
    Returns the configured LLM client based on settings.
    Falls back to local if provider is unknown.
    """
    provider = settings.llm_provider.lower()

    if provider == "openai":
        from clients.openai_client import OpenAIClient
        return OpenAIClient()
    elif provider == "groq":
        from clients.groq_client import GroqClient
        return GroqClient()
    else:
        from clients.local_llm_client import LocalLLMClient
        return LocalLLMClient()