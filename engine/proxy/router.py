"""
Model string parser and provider resolver for proxy mode.

Model string format:  provider/model-name
Examples:
  openai/gpt-4o
  openai/gpt-4o-mini
  ollama/llama3.2
  ollama/mistral
  custom/my-model       (uses openai-compatible base_url from config)
"""

import logging

from db.models import ProxyProviderConfigModel
from engine.proxy.providers.base import BaseProxyProvider
from engine.proxy.providers.openai import OpenAIProxyProvider
from engine.proxy.providers.ollama import OllamaProxyProvider
from security.encryption import decrypt
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.proxy.router")
settings = get_settings()

SUPPORTED_PROVIDERS = {"openai", "ollama", "custom"}


def parse_model_string(model: str) -> tuple[str, str]:
    """
    Parse a model string into (provider, model_name).

    Examples:
      "openai/gpt-4o"    -> ("openai", "gpt-4o")
      "ollama/llama3.2"  -> ("ollama", "llama3.2")

    Raises ValueError with a descriptive message on invalid format.
    """
    if not model or "/" not in model:
        raise ValueError(
            f"Model must be in provider/model format. "
            f"Got: {model!r}. "
            f"Examples: 'openai/gpt-4o', 'ollama/llama3.2'"
        )

    provider, model_name = model.split("/", 1)
    provider   = provider.strip()
    model_name = model_name.strip()

    if not provider:
        raise ValueError(
            f"Provider name is empty in model string: {model!r}"
        )

    if not model_name:
        raise ValueError(
            f"Model name is empty in model string: {model!r}"
        )

    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unsupported provider: {provider!r}. "
            f"Supported providers: {', '.join(sorted(SUPPORTED_PROVIDERS))}"
        )

    return provider, model_name


def resolve_provider(
    provider: str,
    config:   ProxyProviderConfigModel,
) -> tuple[BaseProxyProvider, str | None]:
    """
    Return (provider_instance, decrypted_api_key) for the given provider string.
    decrypted_api_key is None for ollama (no auth required).

    Raises ValueError for unsupported provider.
    Raises ValueError if decryption fails.
    """
    decrypted_key = None

    if config.provider_api_key_enc:
        try:
            decrypted_key = decrypt(config.provider_api_key_enc, settings.secret_key)
        except ValueError as exc:
            raise ValueError(
                "Could not decrypt provider API key. "
                "The application secret_key may have changed."
            ) from exc

    if provider in ("openai", "custom"):
        return OpenAIProxyProvider(
            api_key  = decrypted_key or "",
            base_url = config.base_url,
            timeout  = config.timeout_seconds,
        ), decrypted_key

    if provider == "ollama":
        return OllamaProxyProvider(
            base_url = config.base_url,
            timeout  = config.timeout_seconds,
        ), None

    raise ValueError(
        f"Unsupported provider: {provider!r}. "
        f"Supported providers: {', '.join(sorted(SUPPORTED_PROVIDERS))}"
    )