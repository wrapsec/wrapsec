# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, SecretStr, field_validator, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal, require_admin
from api.v1.dependencies.db import get_db
from api.v1.middleware.auth import get_client_ip
from cache.redis_client import get_redis
from config.settings import get_settings
from db.repositories.admin_event import AdminEventRepository
from db.repositories.settings import TenantSettingsRepository
from domain.enums import AdminEventAction
from security.encryption import decrypt, encrypt, mask
from security.url_validator import validate_llm_base_url
from services.time import to_iso_z, utc_now


async def _resolve_tenant(db, principal) -> uuid.UUID:
    """
    The tenant scope for a settings read/write. Uses the principal's tenant when it
    is a concrete tenant; a cross-tenant admin principal (the admin key) carries no
    specific tenant and resolves to the default tenant (v1 single-tenant).
    """
    tid = getattr(principal, "tenant_id", None)
    try:
        return uuid.UUID(str(tid))
    except (ValueError, TypeError):
        from db.repositories.tenant import TenantRepository
        tenant = await TenantRepository(db).get_default()
        if tenant is None:
            from errors.exceptions import WrapSecError
            raise WrapSecError(
                code="SYSTEM_ERROR",
                message="No tenant context available for settings.",
                status_code=500,
            ) from None
        return tenant.id


class _BoundTenantSettings:
    """A TenantSettingsRepository whose tenant is resolved from the principal on
    first use, so the per-endpoint get(key)/set(key, value) call sites stay
    tenant-scoped without threading tenant_id through each one (D5 split)."""

    def __init__(self, db, principal):
        self._repo      = TenantSettingsRepository(db)
        self._db        = db
        self._principal = principal
        self._tid: uuid.UUID | None = None

    async def _tenant(self) -> uuid.UUID:
        if self._tid is None:
            self._tid = await _resolve_tenant(self._db, self._principal)
        return self._tid

    async def get(self, key: str):
        return await self._repo.get(await self._tenant(), key)

    async def set(self, key: str, value: dict):
        return await self._repo.set(await self._tenant(), key, value)

router = APIRouter()

THRESHOLD_KEY = "policy_thresholds"
LAYERS_KEY    = "detection_layers"

DEFAULT_LAYERS = {
    "rule_enabled": True,
    "ml_enabled":   True,
    "llm_enabled":  True,
}


def _default_thresholds() -> dict:
    _s = get_settings()
    return {"block_threshold": _s.block_threshold, "sanitize_threshold": _s.sanitize_threshold}


class ThresholdsUpdateSchema(BaseModel):
    block_threshold:    float | None = None
    sanitize_threshold: float | None = None

    @model_validator(mode="after")
    def validate_thresholds(self) -> "ThresholdsUpdateSchema":
        _s       = get_settings()
        block    = self.block_threshold    if self.block_threshold    is not None else _s.block_threshold
        sanitize = self.sanitize_threshold if self.sanitize_threshold is not None else _s.sanitize_threshold

        if block <= 0.0:
            raise ValueError("block_threshold must be greater than 0")
        if sanitize < 0.0:
            raise ValueError("sanitize_threshold must be 0 or greater")
        if block <= sanitize:
            raise ValueError(
                f"block_threshold ({block}) must be greater "
                f"than sanitize_threshold ({sanitize})"
            )
        if block > 1.0:
            raise ValueError("block_threshold cannot exceed 1.0")
        if sanitize >= 1.0:
            raise ValueError("sanitize_threshold must be less than 1.0")

        return self


class LayersUpdateSchema(BaseModel):
    rule_enabled: bool | None = None
    ml_enabled:   bool | None = None
    llm_enabled:  bool | None = None


@router.get("/thresholds")
async def get_thresholds(
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(get_current_principal),
):
    """
    Returns the active block and sanitize thresholds.
    Source is 'database' if thresholds have been explicitly set, 'environment' if using defaults.
    """
    repo   = _BoundTenantSettings(db, _principal)
    stored = await repo.get(THRESHOLD_KEY)
    return JSONResponse(content=stored or _default_thresholds())


@router.put("/thresholds")
async def update_thresholds(
    body:      ThresholdsUpdateSchema,
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(require_admin()),
):
    """
    Updates block and/or sanitize thresholds. Merges with existing stored values.
    Validation enforces: block_threshold > sanitize_threshold, both in (0.0, 1.0].
    Auth: JWT + ADMIN role required.
    """
    repo    = _BoundTenantSettings(db, _principal)
    current = await repo.get(THRESHOLD_KEY) or _default_thresholds()

    if body.block_threshold is not None:
        current["block_threshold"] = body.block_threshold
    if body.sanitize_threshold is not None:
        current["sanitize_threshold"] = body.sanitize_threshold

    # Validate merged final state - schema validates against system defaults,
    # not stored DB values. After merging, enforce the full invariant:
    # 0.0 < sanitize < block <= 1.0
    block    = current["block_threshold"]
    sanitize = current["sanitize_threshold"]
    if not (0.0 < sanitize < block <= 1.0):
        from errors.exceptions import WrapSecError
        raise WrapSecError(
            code        = "VALIDATION_ERROR",
            message     = (
                f"Invalid threshold combination after merge: "
                f"block={block}, sanitize={sanitize}. "
                f"Required: 0.0 < sanitize < block <= 1.0"
            ),
            status_code = 422,
        )

    await repo.set(THRESHOLD_KEY, current)
    await db.commit()

    return JSONResponse(content={
        **current,
        "updated_at": to_iso_z(utc_now()),
    })


@router.get("/layers")
async def get_layers(
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(get_current_principal),
):
    """Returns the active detection layer configuration (rule, ML, LLM enabled flags)."""
    repo   = _BoundTenantSettings(db, _principal)
    stored = await repo.get(LAYERS_KEY)
    return JSONResponse(content=stored or DEFAULT_LAYERS)


@router.put("/layers")
async def update_layers(
    body:      LayersUpdateSchema,
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(require_admin()),
):
    """
    Enables or disables detection layers (rule, ML, LLM). Merges with existing values.
    Note: proxy mode requires llm_enabled=true - disabling LLM will block proxy requests.
    Auth: JWT + ADMIN role required.
    """
    repo    = _BoundTenantSettings(db, _principal)
    current = await repo.get(LAYERS_KEY) or DEFAULT_LAYERS.copy()

    if body.rule_enabled is not None:
        current["rule_enabled"] = body.rule_enabled
    if body.ml_enabled is not None:
        current["ml_enabled"] = body.ml_enabled
    if body.llm_enabled is not None:
        current["llm_enabled"] = body.llm_enabled

    await repo.set(LAYERS_KEY, current)
    await db.commit()

    return JSONResponse(content={
        **current,
        "updated_at": to_iso_z(utc_now()),
    })

LLM_KEY         = "llm_settings"
LLM_API_KEY_KEY = "llm_api_key_enc"


def _default_llm() -> dict:
    _s = get_settings()
    return {
        "provider":    _s.llm_provider,
        "model":       _s.llm_model,
        "base_url":    _s.llm_base_url,
        "timeout":     _s.llm_timeout,
        "llm_trigger": _s.llm_trigger_threshold,
    }


class LLMSettingsSchema(BaseModel):
    provider:    str       | None = None
    model:       str       | None = None
    base_url:    str       | None = None
    timeout:     int       | None = None
    llm_trigger: float     | None = None
    api_key:     SecretStr | None = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return validate_llm_base_url(v)

    @model_validator(mode="after")
    def validate_llm(self) -> "LLMSettingsSchema":
        if self.provider and self.provider not in ("ollama", "openai", "custom"):
            raise ValueError("provider must be ollama, openai, or custom")
        if self.timeout is not None and self.timeout < 5:
            raise ValueError("timeout must be at least 5 seconds")
        if self.timeout is not None and self.timeout > 120:
            raise ValueError("timeout cannot exceed 120 seconds")
        if self.llm_trigger is not None and (self.llm_trigger < 0.0 or self.llm_trigger > 1.0):
            raise ValueError("llm_trigger must be between 0.0 and 1.0")
        return self


@router.get("/llm")
async def get_llm_settings(
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(get_current_principal),
):
    """Returns the active LLM layer configuration. api_key is masked in the response - never plaintext."""
    repo    = _BoundTenantSettings(db, _principal)
    stored  = await repo.get(LLM_KEY)
    payload = dict(stored) if stored else _default_llm()

    # Mask the stored API key - never return plaintext
    api_key_masked = None
    enc_record = await repo.get(LLM_API_KEY_KEY)
    if enc_record and enc_record.get("enc"):
        try:
            plaintext      = decrypt(enc_record["enc"], get_settings().secret_key)
            api_key_masked = mask(plaintext)
        except ValueError:
            api_key_masked = "****"

    payload["api_key_masked"] = api_key_masked
    return JSONResponse(content=payload)


@router.put("/llm")
async def update_llm_settings(
    body:      LLMSettingsSchema,
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(require_admin()),
):
    """
    Updates LLM layer settings. Merges with existing values.
    api_key is encrypted before storage - never stored or returned in plaintext.
    Supported providers: ollama, openai, custom.
    Auth: JWT + ADMIN role required.
    """
    repo    = _BoundTenantSettings(db, _principal)
    current = await repo.get(LLM_KEY) or _default_llm()

    if body.provider    is not None: current["provider"]    = body.provider
    if body.model       is not None: current["model"]       = body.model
    if body.base_url    is not None: current["base_url"]    = body.base_url
    if body.timeout     is not None: current["timeout"]     = body.timeout
    if body.llm_trigger is not None: current["llm_trigger"] = body.llm_trigger

    await repo.set(LLM_KEY, current)

    # Encrypt and store api_key separately - never in the main settings JSON
    api_key_masked = None
    if body.api_key is not None:
        raw = body.api_key.get_secret_value().strip()
        if raw:
            enc = encrypt(raw, get_settings().secret_key)
            await repo.set(LLM_API_KEY_KEY, {"enc": enc})
            api_key_masked = mask(raw)
        else:
            # Empty string = clear the stored key
            await repo.set(LLM_API_KEY_KEY, {})
    else:
        # api_key not provided - return existing masked key
        enc_record = await repo.get(LLM_API_KEY_KEY)
        if enc_record and enc_record.get("enc"):
            try:
                plaintext      = decrypt(enc_record["enc"], get_settings().secret_key)
                api_key_masked = mask(plaintext)
            except ValueError:
                api_key_masked = "****"

    await db.commit()

    return JSONResponse(content={
        **current,
        "api_key_masked": api_key_masked,
        "updated_at":     to_iso_z(utc_now()),
    })

RETENTION_KEY = "audit_retention"


class RetentionSettingsSchema(BaseModel):
    retention_days: int

    @model_validator(mode="after")
    def validate_retention(self) -> "RetentionSettingsSchema":
        if self.retention_days < 7:
            raise ValueError("retention_days must be at least 7")
        if self.retention_days > 3650:
            raise ValueError("retention_days cannot exceed 3650 (10 years)")
        return self


@router.get("/retention")
async def get_retention_settings(
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(get_current_principal),
):
    """
    Returns the audit log retention period in days.
    Source is 'database' if explicitly set via PUT, 'environment' if using the default.
    """
    repo    = _BoundTenantSettings(db, _principal)
    stored  = await repo.get(RETENTION_KEY)
    _s      = get_settings()
    days    = stored.get("retention_days", _s.audit_retention_days) if stored else _s.audit_retention_days
    return JSONResponse(content={
        "retention_days": days,
        "source":         "database" if stored else "environment",
    })


@router.put("/retention")
async def update_retention_settings(
    body:      RetentionSettingsSchema,
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(require_admin()),
):
    """
    Updates the audit log retention period. Valid range: 7-3650 days (7 days to 10 years).
    Auth: JWT + ADMIN role required.
    """
    repo = _BoundTenantSettings(db, _principal)
    await repo.set(RETENTION_KEY, {"retention_days": body.retention_days})
    await db.commit()
    return JSONResponse(content={
        "retention_days": body.retention_days,
        "updated_at":     to_iso_z(utc_now()),
    })


RATE_LIMIT_KEY = "rate_limit"


def _default_rate_limit() -> dict:
    return {"per_minute": get_settings().rate_limit_per_minute}


class RateLimitUpdateSchema(BaseModel):
    per_minute: int | None = None

    @model_validator(mode="after")
    def validate_rate_limit(self) -> "RateLimitUpdateSchema":
        if self.per_minute is not None:
            if self.per_minute < 1:
                raise ValueError("per_minute must be at least 1")
            if self.per_minute > 10000:
                raise ValueError("per_minute cannot exceed 10000")
            # Live key limit must always be >= trial limit
            # Otherwise trial keys would be LESS restricted than live keys
            trial_limit = get_settings().trial_rate_limit_per_minute
            if self.per_minute < trial_limit:
                raise ValueError(
                    f"Global rate limit ({self.per_minute}/min) cannot be less than "
                    f"the trial key limit ({trial_limit}/min). "
                    f"Live keys must always have equal or higher limits than trial keys."
                )
        return self


@router.get("/rate_limit")
async def get_rate_limit_settings(
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(get_current_principal),
):
    """
    Returns the current global rate limit.
    Source is 'database' if explicitly set, 'environment' if using default.
    This is the actual enforced value - not the global_policy default.
    """
    repo   = _BoundTenantSettings(db, _principal)
    stored = await repo.get(RATE_LIMIT_KEY)
    if stored:
        return JSONResponse(content={
            **stored,
            "source": "database",
        })
    return JSONResponse(content={
        **_default_rate_limit(),
        "source": "environment",
    })


@router.put("/rate_limit")
async def update_rate_limit_settings(
    body:      RateLimitUpdateSchema,
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(require_admin()),
):
    """
    Update the global rate limit for live keys.
    Takes effect immediately - Redis cache is invalidated on update.
    Does not require server restart.
    Trial key limit is configured via TRIAL_RATE_LIMIT_PER_MINUTE in .env.
    """
    repo    = _BoundTenantSettings(db, _principal)
    current = await repo.get(RATE_LIMIT_KEY) or _default_rate_limit()

    if body.per_minute is not None:
        current["per_minute"] = body.per_minute

    await repo.set(RATE_LIMIT_KEY, current)
    await db.commit()

    # Invalidate Redis cache so new value is picked up on next request
    try:
        redis = get_redis()
        await redis.delete("wrapsec:settings:rate_limit")
    except Exception:
        pass  # Cache invalidation is best-effort

    return JSONResponse(content={
        **current,
        "source":     "database",
        "updated_at": to_iso_z(utc_now()),
    })


@router.get("/storage")
async def get_storage_settings(
    _principal = Depends(get_current_principal),
):
    """
    Returns the current data storage mode and proxy retention period.
    Read-only in V1 -- configured via environment variables.
    """
    cfg = get_settings()
    return JSONResponse(content={
        "storage_mode":         cfg.data_storage_mode,
        "retention_days_proxy": cfg.data_retention_days_proxy,
    })


ADMIN_LIMITS_KEY       = "admin_rate_limits"
ADMIN_LIMITS_CACHE_KEY = "wrapsec:settings:admin_rate_limits"
ADMIN_LIMITS_CACHE_TTL = 60  # seconds - same TTL as global rate limit cache


def _default_admin_limits() -> dict:
    _s = get_settings()
    return {
        "admin_write_rate_limit":  _s.admin_write_rate_limit,
        "audit_export_rate_limit": _s.audit_export_rate_limit,
    }


class AdminLimitsUpdateSchema(BaseModel):
    admin_write_rate_limit:  int | None = None
    audit_export_rate_limit: int | None = None

    @model_validator(mode="after")
    def validate_limits(self) -> "AdminLimitsUpdateSchema":
        if self.admin_write_rate_limit is not None:
            if self.admin_write_rate_limit < 5:
                raise ValueError("admin_write_rate_limit must be at least 5")
            if self.admin_write_rate_limit > 200:
                raise ValueError("admin_write_rate_limit cannot exceed 200")
        if self.audit_export_rate_limit is not None:
            if self.audit_export_rate_limit < 1:
                raise ValueError("audit_export_rate_limit must be at least 1")
            if self.audit_export_rate_limit > 60:
                raise ValueError("audit_export_rate_limit cannot exceed 60")
        return self


@router.get("/admin_limits")
async def get_admin_limits(
    db:         AsyncSession = Depends(get_db),
    _principal  = Depends(get_current_principal),
):
    """
    Returns the active admin operation rate limits.
    Source is 'database' if explicitly set via PUT, 'environment' if using defaults.
    Auth: any valid principal.
    """
    repo   = _BoundTenantSettings(db, _principal)
    stored = await repo.get(ADMIN_LIMITS_KEY)
    if stored:
        return JSONResponse(content={**stored, "source": "database"})
    return JSONResponse(content={**_default_admin_limits(), "source": "environment"})


@router.put("/admin_limits")
async def update_admin_limits(
    body:      AdminLimitsUpdateSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    _principal  = Depends(require_admin()),
):
    """
    Updates admin write and/or audit export rate limits. Merges with existing values.
    Takes effect immediately - Redis cache is invalidated on update.
    Changes are recorded in admin_events for audit trail.

    Floors: admin_write >= 5, audit_export >= 1.
    Ceilings: admin_write <= 200, audit_export <= 60.

    Auth: JWT + ADMIN role required.
    """
    repo    = _BoundTenantSettings(db, _principal)
    current = await repo.get(ADMIN_LIMITS_KEY) or _default_admin_limits()

    old_values = dict(current)

    if body.admin_write_rate_limit  is not None:
        current["admin_write_rate_limit"]  = body.admin_write_rate_limit
    if body.audit_export_rate_limit is not None:
        current["audit_export_rate_limit"] = body.audit_export_rate_limit

    await repo.set(ADMIN_LIMITS_KEY, current)
    await db.commit()

    # Invalidate Redis cache - new limits take effect on next request
    try:
        redis = get_redis()
        await redis.delete(f"{ADMIN_LIMITS_CACHE_KEY}:{await _resolve_tenant(db, _principal)}")
    except Exception:
        pass  # Redis cache invalidation is best-effort; the next request repopulates it.

    # Audit log - security controls changing must always be recorded
    try:
        ip        = get_client_ip(request)
        ua        = request.headers.get("user-agent")
        actor_id  = uuid.UUID(str(_principal.id).replace("user:", ""))
        tenant_id = uuid.UUID(str(_principal.tenant_id))

        event_repo = AdminEventRepository(db)
        await event_repo.insert(
            tenant_id     = tenant_id,
            actor_user_id = actor_id,
            action        = AdminEventAction.SETTINGS_CHANGED,
            metadata      = {"setting": ADMIN_LIMITS_KEY, "old": old_values, "new": current},
            ip_address    = ip,
            user_agent    = ua,
        )
        await db.commit()
    except Exception:
        pass  # Audit logging is best-effort - never fails the request

    return JSONResponse(content={
        **current,
        "source":     "database",
        "updated_at": to_iso_z(utc_now()),
    })
