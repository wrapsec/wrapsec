# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Proxy settings endpoints.
Manages LLM provider configuration for proxy mode (POST /v1/chat/completions).

Endpoints:
    GET    /v1/settings/proxy          -- get current config (api key masked)
    PUT    /v1/settings/proxy          -- create or replace config
    DELETE /v1/settings/proxy          -- remove config
    GET    /v1/settings/proxy/health   -- test provider connectivity
"""

import ipaddress
import logging
import time
from typing import Literal
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, field_validator, HttpUrl, SecretStr
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal
from api.v1.dependencies.db import get_db
from domain.entities.principal import Principal
from config.settings import get_settings
from db.models import ProxyProviderConfigModel
from security.encryption import encrypt, decrypt, mask

router = APIRouter()
logger = logging.getLogger("wrapsec.proxy.settings")

SUPPORTED_PROVIDERS = {"openai", "ollama", "custom"}

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
_BLOCKED_HOSTS = frozenset({"localhost", "metadata.google.internal", "metadata.goog"})


def _is_ssrf_target(url: str) -> bool:
    """Return True if the URL targets a private, loopback, or cloud-metadata address."""
    host = (urlparse(url).hostname or "").lower()
    if host in _BLOCKED_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ── Schemas ────────────────────────────────────────────────────────────────────

class ProxySettingsPutSchema(BaseModel):
    provider:      str
    base_url:      str
    api_key:       SecretStr | None = None
    default_model: str
    timeout:       int = 60

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        if v not in SUPPORTED_PROVIDERS:
            raise ValueError(
                f"provider must be one of: {', '.join(sorted(SUPPORTED_PROVIDERS))}"
            )
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if not (1 <= v <= 300):
            raise ValueError("timeout must be between 1 and 300 seconds")
        return v

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        v = v.rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        if _is_ssrf_target(v):
            raise ValueError("base_url must not target private or internal addresses")
        return v

    @field_validator("default_model")
    @classmethod
    def validate_model(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("default_model must not be empty")
        return v


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_config_response(config: ProxyProviderConfigModel) -> dict:
    """Build the safe response dict -- api key is always masked."""
    masked = None
    if config.provider_api_key_enc:
        try:
            plaintext = decrypt(config.provider_api_key_enc, get_settings().secret_key)
            masked    = mask(plaintext)
        except ValueError:
            masked = "****"

    return {
        "provider":              config.provider,
        "base_url":              config.base_url,
        "api_key_masked":        masked,
        "default_model":         config.default_model,
        "timeout_seconds":       config.timeout_seconds,
        "created_at":            config.created_at.isoformat() if config.created_at else None,
        "updated_at":            config.updated_at.isoformat() if config.updated_at else None,
    }


async def _get_config(key_id: str, db: AsyncSession) -> ProxyProviderConfigModel | None:
    result = await db.execute(
        select(ProxyProviderConfigModel).where(
            ProxyProviderConfigModel.key_id == key_id
        )
    )
    return result.scalar_one_or_none()


# ── GET /v1/settings/proxy ─────────────────────────────────────────────────────

@router.get("/proxy")
async def get_proxy_settings(
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Returns the proxy provider config for the current API key.
    The provider API key is always masked in the response — never returned in plaintext.
    404 if no provider has been configured.
    """
    key_id = request.state.key_id
    config = await _get_config(key_id, db)

    if not config:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": "No proxy provider configured."}},
        )

    return JSONResponse(status_code=200, content=_build_config_response(config))


# ── PUT /v1/settings/proxy ─────────────────────────────────────────────────────

@router.put("/proxy")
async def put_proxy_settings(
    request:    Request,
    body:       ProxySettingsPutSchema,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Creates or replaces the proxy provider config for the current API key (upsert).
    The provider API key is encrypted before storage using the server's secret_key.
    Providers "openai" and "custom" require api_key; "ollama" does not.
    """
    key_id = request.state.key_id

    # Validate: openai and custom providers require an api_key
    if body.provider in ("openai", "custom") and not (body.api_key and body.api_key.get_secret_value()):
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code":    "VALIDATION_ERROR",
                    "message": f"api_key is required for provider '{body.provider}'",
                }
            },
        )

    # Encrypt the api_key before storing
    encrypted_key = None
    if body.api_key:
        encrypted_key = encrypt(body.api_key.get_secret_value(), get_settings().secret_key)

    existing = await _get_config(key_id, db)

    if existing:
        # Update in place
        existing.provider             = body.provider
        existing.base_url             = body.base_url
        existing.provider_api_key_enc = encrypted_key
        existing.default_model        = body.default_model
        existing.timeout_seconds      = body.timeout
        config = existing
    else:
        # Create new
        config = ProxyProviderConfigModel(
            key_id               = key_id,
            provider             = body.provider,
            base_url             = body.base_url,
            provider_api_key_enc = encrypted_key,
            default_model        = body.default_model,
            timeout_seconds      = body.timeout,
        )
        db.add(config)

    await db.commit()
    await db.refresh(config)

    logger.info(f"Proxy config saved for key_id={key_id} provider={body.provider}")

    return JSONResponse(status_code=200, content=_build_config_response(config))


# ── DELETE /v1/settings/proxy ──────────────────────────────────────────────────

@router.delete("/proxy")
async def delete_proxy_settings(
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Removes the proxy provider config for the current API key.
    After deletion, proxy mode requests will fail with proxy_not_configured.
    404 if no config exists.
    """
    key_id = request.state.key_id
    result = await db.execute(
        delete(ProxyProviderConfigModel).where(
            ProxyProviderConfigModel.key_id == key_id
        )
    )
    await db.commit()

    if result.rowcount == 0:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": "No proxy provider configured."}},
        )

    logger.info(f"Proxy config deleted for key_id={key_id}")
    return Response(status_code=204)


# ── GET /v1/settings/proxy/health ──────────────────────────────────────────────

@router.get("/proxy/health")
async def get_proxy_health(
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Tests live connectivity to the configured LLM provider.
    Always returns HTTP 200 — reachable=true/false indicates the provider status.
    Ollama: GET /api/tags. OpenAI-compatible: GET /models with Authorization header.
    Timeout for the connectivity check is fixed at 10 seconds.
    """
    key_id = request.state.key_id
    config = await _get_config(key_id, db)

    if not config:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": "No proxy provider configured."}},
        )

    # Decrypt api key for the connectivity check
    api_key = None
    if config.provider_api_key_enc:
        try:
            api_key = decrypt(config.provider_api_key_enc, get_settings().secret_key)
        except ValueError:
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code":    "DECRYPTION_ERROR",
                        "message": "Could not decrypt provider API key. "
                                   "secret_key may have changed.",
                    }
                },
            )

    start = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            if config.provider == "ollama":
                # Ollama: GET /api/tags to verify the server is up
                resp = await client.get(f"{config.base_url}/api/tags")
            else:
                # OpenAI-compatible: GET /models to verify auth and connectivity
                resp = await client.get(
                    f"{config.base_url}/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
            resp.raise_for_status()
            latency_ms = int((time.monotonic() - start) * 1000)

            logger.info(
                f"Health check OK for key_id={key_id} "
                f"provider={config.provider} latency={latency_ms}ms"
            )

            return JSONResponse(
                status_code=200,
                content={
                    "provider":      config.provider,
                    "base_url":      config.base_url,
                    "default_model": config.default_model,
                    "reachable":     True,
                    "latency_ms":    latency_ms,
                },
            )

    except httpx.TimeoutException:
        return JSONResponse(
            status_code=200,
            content={
                "provider":  config.provider,
                "base_url":  config.base_url,
                "reachable": False,
                "error":     "Connection timed out after 10 seconds",
            },
        )
    except httpx.ConnectError:
        return JSONResponse(
            status_code=200,
            content={
                "provider":  config.provider,
                "base_url":  config.base_url,
                "reachable": False,
                "error":     "Connection refused.",
            },
        )
    except httpx.HTTPStatusError as exc:
        return JSONResponse(
            status_code=200,
            content={
                "provider":  config.provider,
                "base_url":  config.base_url,
                "reachable": False,
                "error":     f"HTTP {exc.response.status_code}",
            },
        )
    except Exception as exc:
        logger.error("Health check failed for key_id=%s: %s", key_id, exc)
        return JSONResponse(
            status_code=200,
            content={
                "provider":  config.provider,
                "base_url":  config.base_url,
                "reachable": False,
                "error":     "Health check failed.",
            },
        )