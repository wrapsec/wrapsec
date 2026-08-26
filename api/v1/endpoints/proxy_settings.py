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

import logging
import time
from typing import Any, cast

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, SecretStr, field_validator
from sqlalchemy import CursorResult, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import require_any_admin
from api.v1.dependencies.db import get_db
from api.v1.schemas.response import ErrorEnvelope, ProxyProviderConfigResponse
from config.settings import get_settings
from db.models import ProxyProviderConfigModel
from domain.entities.principal import Principal
from errors.catalog import VALIDATION_CATALOG, ValidationCode
from errors.exceptions import NotFoundError, WrapSecError
from security.encryption import decrypt, encrypt, mask
from security.url_validator import validate_llm_base_url
from services.time import to_iso_z

router = APIRouter()

# Reachable failures on the three PUBLIC proxy-settings routes. All three now
# answer with the catalog envelope, so every entry below describes the body the
# runtime actually sends.
_PROXY_SETTINGS_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Missing or invalid credentials."},
    403: {"model": ErrorEnvelope, "description": "Proxy provider configuration is admin-only, on reads as well as writes."},
}

# The read and the delete answer 404 when this tenant has no provider row. The
# upsert does not: it creates one, so a 404 there would document a status it
# cannot produce.
_PROXY_SETTINGS_MISSING: dict[int | str, dict[str, Any]] = {
    **_PROXY_SETTINGS_ERRORS,
    404: {"model": ErrorEnvelope, "description": "This tenant has no proxy provider configured."},
}
logger = logging.getLogger("wrapsec.proxy.settings")

SUPPORTED_PROVIDERS = {"openai", "ollama", "custom"}


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
        return validate_llm_base_url(v)

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
        "created_at":            to_iso_z(config.created_at) if config.created_at else None,
        "updated_at":            to_iso_z(config.updated_at) if config.updated_at else None,
    }


async def _get_config(tenant_id: str, db: AsyncSession) -> ProxyProviderConfigModel | None:
    result = await db.execute(
        select(ProxyProviderConfigModel).where(
            ProxyProviderConfigModel.tenant_id == tenant_id
        )
    )
    return result.scalar_one_or_none()


# ── GET /v1/settings/proxy ─────────────────────────────────────────────────────

@router.get(
    "/proxy",
    response_model               = ProxyProviderConfigResponse,
    response_model_exclude_unset = True,
    responses                    = _PROXY_SETTINGS_MISSING,
)
async def get_proxy_settings(
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(require_any_admin()),
):
    """
    Returns the proxy provider config for the current tenant.
    The provider API key is always masked in the response - never returned in plaintext.
    404 if no provider has been configured.
    """
    tenant_id = request.state.tenant_id
    config = await _get_config(tenant_id, db)

    if not config:
        # The catalog envelope, like every other error on this surface. The
        # resource name is all the caller learns: `params` carries only
        # "proxy provider", and the tenant id travels in `debug_message`, which
        # is logged and never serialized. So the response still says no more
        # than "this tenant has no provider configured".
        raise NotFoundError(resource="proxy_provider", identifier=tenant_id)

    # A value, not a JSONResponse: a Response object bypasses the model.
    return _build_config_response(config)


# ── PUT /v1/settings/proxy ─────────────────────────────────────────────────────

@router.put(
    "/proxy",
    response_model               = ProxyProviderConfigResponse,
    response_model_exclude_unset = True,
    responses = {
        **_PROXY_SETTINGS_ERRORS,
        422: {"model": ErrorEnvelope, "description": "Request body failed validation."},
    },
)
async def put_proxy_settings(
    request:    Request,
    body:       ProxySettingsPutSchema,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(require_any_admin()),
):
    """
    Creates or replaces the proxy provider config for the current tenant (upsert).
    The provider API key is encrypted before storage using the server's secret_key.
    Providers "openai" and "custom" require api_key; "ollama" does not.
    """
    tenant_id = request.state.tenant_id

    # Validate: openai and custom providers require an api_key.
    #
    # Raised rather than returned, so the global handler builds the same envelope
    # the OTHER 422 on this route already returns -- request-schema validation.
    # One status answering with two different shapes is what made the published
    # `422: ErrorEnvelope` a false statement.
    #
    # VALIDATION_ERROR is carried as an explicit code because the exception class
    # named `ValidationError` maps to INVALID_REQUEST/400; using it here would
    # move this rejection to 400. This matches the existing `WrapSecError(code=,
    # status_code=)` convention for a 422 raised by handler logic.
    #
    # The provider name is NOT reflected into the public message. The condition
    # is per-field, and `invalid_params` is the canonical place for it: a form
    # client gets the field and a localizable REQUIRED code instead of an English
    # sentence quoting the caller's own input back at them.
    if body.provider in ("openai", "custom") and not (body.api_key and body.api_key.get_secret_value()):
        raise WrapSecError(
            code           = "VALIDATION_ERROR",
            status_code    = 422,
            debug_message  = f"api_key is required for provider {body.provider!r}",
            invalid_params = [{
                "field":  "api_key",
                "code":   ValidationCode.REQUIRED.value,
                "key":    VALIDATION_CATALOG[ValidationCode.REQUIRED],
                "params": {},
            }],
        )

    # Encrypt the api_key before storing
    encrypted_key = None
    if body.api_key:
        encrypted_key = encrypt(body.api_key.get_secret_value(), get_settings().secret_key)

    existing = await _get_config(tenant_id, db)

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
            tenant_id            = tenant_id,
            provider             = body.provider,
            base_url             = body.base_url,
            provider_api_key_enc = encrypted_key,
            default_model        = body.default_model,
            timeout_seconds      = body.timeout,
        )
        db.add(config)

    await db.commit()
    await db.refresh(config)

    logger.info(f"Proxy config saved for tenant_id={tenant_id} provider={body.provider}")

    # A value, not a JSONResponse: a Response object bypasses the model.
    return _build_config_response(config)


# ── DELETE /v1/settings/proxy ──────────────────────────────────────────────────

@router.delete(
    "/proxy",
    # NO response model, deliberately: this route answers 204 with an empty body.
    # A model describes a body, and there is none to describe -- recorded in
    # NON_MODEL_ROUTES with that reason rather than given an empty schema.
    status_code = 204,
    responses   = _PROXY_SETTINGS_MISSING,
)
async def delete_proxy_settings(
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(require_any_admin()),
):
    """
    Removes the proxy provider config for the current tenant.
    After deletion, proxy mode requests will fail with proxy_not_configured.
    404 if no config exists.
    """
    tenant_id = request.state.tenant_id
    result = await db.execute(
        delete(ProxyProviderConfigModel).where(
            ProxyProviderConfigModel.tenant_id == tenant_id
        )
    )
    await db.commit()

    if cast(CursorResult, result).rowcount == 0:
        # Same envelope and same disclosure as the read above.
        raise NotFoundError(resource="proxy_provider", identifier=tenant_id)

    logger.info(f"Proxy config deleted for tenant_id={tenant_id}")
    return Response(status_code=204)


# ── GET /v1/settings/proxy/health ──────────────────────────────────────────────

# Operator reachability probe against the configured provider, not part of
# the integrator contract.
@router.get("/proxy/health", include_in_schema=False)
async def get_proxy_health(
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(require_any_admin()),
):
    """
    Tests live connectivity to the configured LLM provider.
    Always returns HTTP 200 - reachable=true/false indicates the provider status.
    Ollama: GET /api/tags. OpenAI-compatible: GET /models with Authorization header.
    Timeout for the connectivity check is fixed at 10 seconds.
    """
    tenant_id = request.state.tenant_id
    config = await _get_config(tenant_id, db)

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
                f"Health check OK for tenant_id={tenant_id} "
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
        logger.error("Health check failed for tenant_id=%s: %s", tenant_id, exc)
        return JSONResponse(
            status_code=200,
            content={
                "provider":  config.provider,
                "base_url":  config.base_url,
                "reachable": False,
                "error":     "Health check failed.",
            },
        )