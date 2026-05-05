from config.settings import get_settings
from interfaces.base_llm import BaseLLMClient


async def get_llm_settings_from_db() -> dict:
    """Load LLM settings from DB — falls back to .env defaults."""
    try:
        import os
        if os.getenv("TESTING") == "true":
            return {}
        from db.session import AsyncSessionFactory
        from db.repositories.settings import SettingsRepository
        async with AsyncSessionFactory() as session:
            repo   = SettingsRepository(session)
            stored = await repo.get("llm_settings")
            return stored or {}
    except Exception:
        return {}


def get_llm_client(llm_settings: dict | None = None) -> BaseLLMClient:
    """
    Returns the configured LLM client.
    llm_settings from DB overrides .env settings.
    """
    _settings = get_settings()
    provider = (
        (llm_settings or {}).get("provider")
        or _settings.llm_provider
    ).lower()

    if provider == "openai":
        from clients.openai_client import OpenAIClient
        return OpenAIClient(llm_settings=llm_settings)
    elif provider == "groq":
        from clients.groq_client import GroqClient
        return GroqClient(llm_settings=llm_settings)
    else:
        from clients.local_llm_client import LocalLLMClient
        return LocalLLMClient(llm_settings=llm_settings)