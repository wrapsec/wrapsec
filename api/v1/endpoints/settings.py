# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.db import get_db
from api.v1.dependencies.auth import get_current_principal, require_admin
from db.repositories.settings import SettingsRepository
from config.settings import get_settings
from errors.exceptions import ValidationError

router    = APIRouter()
settings  = get_settings()

THRESHOLD_KEY = "policy_thresholds"
LAYERS_KEY    = "detection_layers"

DEFAULT_THRESHOLDS = {
    "block_threshold":    settings.block_threshold,
    "sanitize_threshold": settings.sanitize_threshold,
}

DEFAULT_LAYERS = {
    "rule_enabled": True,
    "ml_enabled":   True,
    "llm_enabled":  True,
}


class ThresholdsUpdateSchema(BaseModel):
    block_threshold:    float | None = None
    sanitize_threshold: float | None = None

    @model_validator(mode="after")
    def validate_thresholds(self) -> "ThresholdsUpdateSchema":
        block    = self.block_threshold    if self.block_threshold    is not None else settings.block_threshold
        sanitize = self.sanitize_threshold if self.sanitize_threshold is not None else settings.sanitize_threshold

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
    repo   = SettingsRepository(db)
    stored = await repo.get(THRESHOLD_KEY)
    return JSONResponse(content=stored or DEFAULT_THRESHOLDS)


@router.put("/thresholds")
async def update_thresholds(
    body:      ThresholdsUpdateSchema,
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(require_admin()),
):
    repo    = SettingsRepository(db)
    current = await repo.get(THRESHOLD_KEY) or DEFAULT_THRESHOLDS.copy()

    if body.block_threshold is not None:
        current["block_threshold"] = body.block_threshold
    if body.sanitize_threshold is not None:
        current["sanitize_threshold"] = body.sanitize_threshold

    await repo.set(THRESHOLD_KEY, current)

    return JSONResponse(content={
        **current,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


@router.get("/layers")
async def get_layers(
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(get_current_principal),
):
    repo   = SettingsRepository(db)
    stored = await repo.get(LAYERS_KEY)
    return JSONResponse(content=stored or DEFAULT_LAYERS)


@router.put("/layers")
async def update_layers(
    body:      LayersUpdateSchema,
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(require_admin()),
):
    repo    = SettingsRepository(db)
    current = await repo.get(LAYERS_KEY) or DEFAULT_LAYERS.copy()

    if body.rule_enabled is not None:
        current["rule_enabled"] = body.rule_enabled
    if body.ml_enabled is not None:
        current["ml_enabled"] = body.ml_enabled
    if body.llm_enabled is not None:
        current["llm_enabled"] = body.llm_enabled

    await repo.set(LAYERS_KEY, current)

    return JSONResponse(content={
        **current,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })

LLM_KEY = "llm_settings"

DEFAULT_LLM = {
    "provider":    settings.llm_provider,
    "model":       settings.llm_model,
    "base_url":    settings.llm_base_url,
    "timeout":     settings.llm_timeout,
    "llm_trigger": settings.llm_trigger_threshold,
}


class LLMSettingsSchema(BaseModel):
    provider:    str   | None = None
    model:       str   | None = None
    base_url:    str   | None = None
    timeout:     int   | None = None
    llm_trigger: float | None = None

    @model_validator(mode="after")
    def validate_llm(self) -> "LLMSettingsSchema":
        if self.provider and self.provider not in ("ollama", "openai", "groq"):
            raise ValueError("provider must be ollama, openai, or groq")
        if self.timeout is not None and self.timeout < 5:
            raise ValueError("timeout must be at least 5 seconds")
        if self.timeout is not None and self.timeout > 120:
            raise ValueError("timeout cannot exceed 120 seconds")
        if self.llm_trigger is not None:
            if self.llm_trigger < 0.0 or self.llm_trigger > 1.0:
                raise ValueError("llm_trigger must be between 0.0 and 1.0")
        return self


@router.get("/llm")
async def get_llm_settings(
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(get_current_principal),
):
    repo   = SettingsRepository(db)
    stored = await repo.get(LLM_KEY)
    return JSONResponse(content=stored or DEFAULT_LLM)


@router.put("/llm")
async def update_llm_settings(
    body:      LLMSettingsSchema,
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(require_admin()),
):
    repo    = SettingsRepository(db)
    current = await repo.get(LLM_KEY) or DEFAULT_LLM.copy()

    if body.provider    is not None: current["provider"]    = body.provider
    if body.model       is not None: current["model"]       = body.model
    if body.base_url    is not None: current["base_url"]    = body.base_url
    if body.timeout     is not None: current["timeout"]     = body.timeout
    if body.llm_trigger is not None: current["llm_trigger"] = body.llm_trigger

    await repo.set(LLM_KEY, current)

    return JSONResponse(content={
        **current,
        "updated_at": datetime.now(timezone.utc).isoformat(),
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
    repo    = SettingsRepository(db)
    stored  = await repo.get(RETENTION_KEY)
    days    = stored.get("retention_days", settings.audit_retention_days) if stored else settings.audit_retention_days
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
    repo = SettingsRepository(db)
    await repo.set(RETENTION_KEY, {"retention_days": body.retention_days})
    return JSONResponse(content={
        "retention_days": body.retention_days,
        "updated_at":     datetime.now(timezone.utc).isoformat(),
    })


RATE_LIMIT_KEY = "rate_limit"

DEFAULT_RATE_LIMIT = {
    "per_minute": settings.rate_limit_per_minute,
}


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
            trial_limit = settings.trial_rate_limit_per_minute
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
    This is the actual enforced value — not the global_policy default.
    """
    repo   = SettingsRepository(db)
    stored = await repo.get(RATE_LIMIT_KEY)
    if stored:
        return JSONResponse(content={
            **stored,
            "source": "database",
        })
    return JSONResponse(content={
        **DEFAULT_RATE_LIMIT,
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
    Takes effect immediately — Redis cache is invalidated on update.
    Does not require server restart.
    Trial key limit is configured via TRIAL_RATE_LIMIT_PER_MINUTE in .env.
    """
    repo    = SettingsRepository(db)
    current = await repo.get(RATE_LIMIT_KEY) or DEFAULT_RATE_LIMIT.copy()

    if body.per_minute is not None:
        current["per_minute"] = body.per_minute

    await repo.set(RATE_LIMIT_KEY, current)

    # Invalidate Redis cache so new value is picked up on next request
    try:
        from cache.redis_client import get_redis
        redis = get_redis()
        await redis.delete("wrapsec:settings:rate_limit")
    except Exception:
        pass  # Cache invalidation is best-effort

    return JSONResponse(content={
        **current,
        "source":     "database",
        "updated_at": datetime.now(timezone.utc).isoformat(),
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
