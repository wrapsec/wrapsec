"""
Proxy settings endpoints.
Manages LLM provider configuration for proxy mode (POST /v1/chat/completions).

Endpoints:
    GET    /v1/settings/proxy          -- get current config (api key masked)
    PUT    /v1/settings/proxy          -- create or replace config
    DELETE /v1/settings/proxy          -- remove config
    GET    /v1/settings/proxy/health   -- test provider connectivity
"""

import logging
import time
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, HttpUrl
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.db import get_db
from config.settings import get_settings
from db.models import ProxyProviderConfigModel
from security.encryption import encrypt, decrypt, mask

router   = APIRouter()
settings = get_settings()
logger   = logging.getLogger("wrapsec.proxy.settings")

SUPPORTED_PROVIDERS = {"openai", "ollama", "custom"}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ProxySettingsPutSchema(BaseModel):
    provider:      str
    base_url:      str
    api_key:       str | None = None
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
        return v

    @field_validator("default_model")
    @classmethod
    def validate_model(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("default_model must not be empty")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_config_response(config: ProxyProviderConfigModel) -> dict:
    """Build the safe response dict -- api key is always masked."""
    masked = None
    if config.provider_api_key_enc:
        try:
            plaintext = decrypt(config.provider_api_key_enc, settings.secret_key)
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


# ---------------------------------------------------------------------------
# GET /v1/settings/proxy
# ---------------------------------------------------------------------------

@router.get("/proxy")
async def get_proxy_settings(
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    key_id = request.state.key_id
    config = await _get_config(key_id, db)

    if not config:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": "No proxy provider configured."}},
        )

    return JSONResponse(status_code=200, content=_build_config_response(config))


# ---------------------------------------------------------------------------
# PUT /v1/settings/proxy
# ---------------------------------------------------------------------------

@router.put("/proxy")
async def put_proxy_settings(
    request: Request,
    body:    ProxySettingsPutSchema,
    db:      AsyncSession = Depends(get_db),
):
    key_id = request.state.key_id

    # Validate: openai and custom providers require an api_key
    if body.provider in ("openai", "custom") and not body.api_key:
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
        encrypted_key = encrypt(body.api_key, settings.secret_key)

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


# ---------------------------------------------------------------------------
# DELETE /v1/settings/proxy
# ---------------------------------------------------------------------------

@router.delete("/proxy")
async def delete_proxy_settings(
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
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
    return JSONResponse(status_code=204, content=None)


# ---------------------------------------------------------------------------
# GET /v1/settings/proxy/health
# ---------------------------------------------------------------------------

@router.get("/proxy/health")
async def get_proxy_health(
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
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
            api_key = decrypt(config.provider_api_key_enc, settings.secret_key)
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
    except httpx.ConnectError as exc:
        return JSONResponse(
            status_code=200,
            content={
                "provider":  config.provider,
                "base_url":  config.base_url,
                "reachable": False,
                "error":     f"Connection refused: {exc}",
            },
        )
    except httpx.HTTPStatusError as exc:
        return JSONResponse(
            status_code=200,
            content={
                "provider":  config.provider,
                "base_url":  config.base_url,
                "reachable": False,
                "error":     f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            },
        )
    except Exception as exc:
        logger.error(f"Health check failed for key_id={key_id}: {exc}")
        return JSONResponse(
            status_code=200,
            content={
                "provider":  config.provider,
                "base_url":  config.base_url,
                "reachable": False,
                "error":     str(exc),
            },
        )