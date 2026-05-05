# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.auth import get_current_principal
from api.v1.dependencies.db import get_db
from domain.entities.principal import Principal
from config.settings import get_settings

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status":  "ok",
        "version": get_settings().app_version,
    }


@router.get("/health/ready")
async def health_ready():
    """
    Readiness check. Returns "ready" if all critical components are healthy.
    Checks: database connectivity, Redis availability, ML model load status.
    Used by container orchestrators to hold traffic until the service is ready.
    """
    from cache.redis_client import ping as redis_ping
    from db.session import AsyncSessionFactory

    # Database ping
    db_ok = False
    try:
        async with AsyncSessionFactory() as session:
            await session.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    # Redis ping
    redis_ok = await redis_ping()

    # ML model check — verify the model file was loaded at startup
    ml_ok = False
    try:
        from engine.detection.ml_detector import MLDetector
        ml_ok = MLDetector.is_model_loaded()
    except Exception:
        ml_ok = False

    checks = {
        "database": "ok" if db_ok else "unavailable",
        "redis":    "ok" if redis_ok else "unavailable",
        "ml_model": "ok" if ml_ok else "unavailable",
    }
    all_ok = all(v == "ok" for v in checks.values())

    return {
        "status": "ready" if all_ok else "degraded",
        "checks": checks,
    }


@router.get("/health/live")
async def health_live():
    return {"status": "alive"}


@router.get("/health/config")
async def health_config(
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Returns the currently active system configuration.
    Useful for deployment verification and debugging.
    Does not expose API keys or secrets.
    """
    from db.repositories.settings import SettingsRepository

    _settings         = get_settings()
    repo              = SettingsRepository(db)
    stored_thresholds = await repo.get("policy_thresholds") or {}
    stored_layers     = await repo.get("detection_layers")  or {}
    stored_llm        = await repo.get("llm_settings")      or {}
    stored_rate_limit = await repo.get("rate_limit")        or {}

    return {
        "version": _settings.app_version,
        "thresholds": {
            "block":    stored_thresholds.get("block_threshold",    _settings.block_threshold),
            "sanitize": stored_thresholds.get("sanitize_threshold", _settings.sanitize_threshold),
            "source":   "database" if stored_thresholds else "environment",
        },
        "detection_layers": {
            "rule":   stored_layers.get("rule_enabled", True),
            "ml":     stored_layers.get("ml_enabled",   True),
            "llm":    stored_layers.get("llm_enabled",  True),
            "source": "database" if stored_layers else "environment",
        },
        "llm": {
            "provider":    stored_llm.get("provider",    _settings.llm_provider),
            "model":       stored_llm.get("model",       _settings.llm_model),
            "llm_trigger": stored_llm.get("llm_trigger", _settings.llm_trigger_threshold),
            "timeout":     stored_llm.get("timeout",     _settings.llm_timeout),
            "source":      "database" if stored_llm else "environment",
        },
        "rate_limit": {
            "per_minute": stored_rate_limit.get("per_minute", _settings.rate_limit_per_minute),
            "source":     "database" if stored_rate_limit else "environment",
        },
    }