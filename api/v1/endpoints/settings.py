# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.db import get_db
from api.v1.dependencies.auth import get_current_principal, require_admin
from cache.redis_client import get_redis
from db.repositories.settings import SettingsRepository
from config.settings import get_settings
from errors.exceptions import ValidationError

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
    repo   = SettingsRepository(db)
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
    repo    = SettingsRepository(db)
    current = await repo.get(THRESHOLD_KEY) or _default_thresholds()

    if body.block_threshold is not None:
        current["block_threshold"] = body.block_threshold
    if body.sanitize_threshold is not None:
        current["sanitize_threshold"] = body.sanitize_threshold

    await repo.set(THRESHOLD_KEY, current)
    await db.commit()

    return JSONResponse(content={
        **current,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


@router.get("/layers")
async def get_layers(
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(get_current_principal),
):
    """Returns the active detection layer configuration (rule, ML, LLM enabled flags)."""
    repo   = SettingsRepository(db)
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
    Note: proxy mode requires llm_enabled=true — disabling LLM will block proxy requests.
    Auth: JWT + ADMIN role required.
    """
    repo    = SettingsRepository(db)
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
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })

LLM_KEY = "llm_settings"

_LLM_PRIVATE_NETS = [
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
_LLM_BLOCKED_HOSTS = frozenset({"localhost", "metadata.google.internal", "metadata.goog"})


def _is_ssrf_target(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if host in _LLM_BLOCKED_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _LLM_PRIVATE_NETS)
    except ValueError:
        return False


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
    provider:    str   | None = None
    model:       str   | None = None
    base_url:    str   | None = None
    timeout:     int   | None = None
    llm_trigger: float | None = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        if _is_ssrf_target(v):
            raise ValueError("base_url must not target private or internal addresses")
        return v

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
    """Returns the active LLM layer configuration (provider, model, base_url, timeout, llm_trigger threshold)."""
    repo   = SettingsRepository(db)
    stored = await repo.get(LLM_KEY)
    return JSONResponse(content=stored or _default_llm())


@router.put("/llm")
async def update_llm_settings(
    body:      LLMSettingsSchema,
    db:        AsyncSession = Depends(get_db),
    _principal = Depends(require_admin()),
):
    """
    Updates LLM layer settings. Merges with existing values.
    Supported providers: ollama, openai, groq.
    Auth: JWT + ADMIN role required.
    """
    repo    = SettingsRepository(db)
    current = await repo.get(LLM_KEY) or _default_llm()

    if body.provider    is not None: current["provider"]    = body.provider
    if body.model       is not None: current["model"]       = body.model
    if body.base_url    is not None: current["base_url"]    = body.base_url
    if body.timeout     is not None: current["timeout"]     = body.timeout
    if body.llm_trigger is not None: current["llm_trigger"] = body.llm_trigger

    await repo.set(LLM_KEY, current)
    await db.commit()

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
    """
    Returns the audit log retention period in days.
    Source is 'database' if explicitly set via PUT, 'environment' if using the default.
    """
    repo    = SettingsRepository(db)
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
    Updates the audit log retention period. Valid range: 7–3650 days (7 days to 10 years).
    Auth: JWT + ADMIN role required.
    """
    repo = SettingsRepository(db)
    await repo.set(RETENTION_KEY, {"retention_days": body.retention_days})
    await db.commit()
    return JSONResponse(content={
        "retention_days": body.retention_days,
        "updated_at":     datetime.now(timezone.utc).isoformat(),
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
    Takes effect immediately — Redis cache is invalidated on update.
    Does not require server restart.
    Trial key limit is configured via TRIAL_RATE_LIMIT_PER_MINUTE in .env.
    """
    repo    = SettingsRepository(db)
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
