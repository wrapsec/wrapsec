from config.settings import get_settings
from interfaces.base_llm import BaseLLMClient


async def get_llm_settings_from_db() -> dict:
    """Load LLM settings from DB - falls back to .env defaults. Decrypts stored API key."""
    try:
        import os
        if os.getenv("TESTING") == "true":
            return {}
        from db.repositories.settings import TenantSettingsRepository
        from db.repositories.tenant import TenantRepository
        from db.session import AsyncSessionFactory
        from security.encryption import decrypt
        async with AsyncSessionFactory() as session:
            # v1 single-tenant: the default tenant's LLM config. (Per-tenant LLM
            # config via the resolved policy is a later refinement.)
            tenant = await TenantRepository(session).get_bootstrap_default()
            if tenant is None:
                return {}
            repo    = TenantSettingsRepository(session)
            stored  = await repo.get(tenant.id, "llm_settings")
            result  = dict(stored) if stored else {}

            # Decrypt and inject API key if stored
            enc_record = await repo.get(tenant.id, "llm_api_key_enc")
            if enc_record and enc_record.get("enc"):
                try:
                    result["api_key"] = decrypt(enc_record["enc"], get_settings().secret_key)
                except ValueError:
                    pass  # Decryption failure - fall back to env var

            return result
    except Exception:
        return {}


def get_llm_client(llm_settings: dict | None = None) -> BaseLLMClient:
    """
    Returns the configured LLM client.
    llm_settings from DB overrides .env settings.
    Both openai and custom providers use OpenAIClient (OpenAI-compatible protocol).
    """
    _settings = get_settings()
    provider = (
        (llm_settings or {}).get("provider")
        or _settings.llm_provider
    ).lower()

    if provider in ("openai", "custom"):
        from clients.openai_client import OpenAIClient
        return OpenAIClient(llm_settings=llm_settings)
    else:
        from clients.local_llm_client import LocalLLMClient
        return LocalLLMClient(llm_settings=llm_settings)