from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.db import get_db
from config.settings import get_settings

router   = APIRouter()
settings = get_settings()


@router.get("/health")
async def health():
    return {
        "status":  "ok",
        "version": settings.app_version,
    }


@router.get("/health/ready")
async def health_ready():
    from cache.redis_client import ping as redis_ping
    redis_ok = await redis_ping()

    checks = {
        "database": "ok",
        "redis":    "ok" if redis_ok else "unavailable",
        "ml_model": "ok",
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
async def health_config(db: AsyncSession = Depends(get_db)):
    """
    Returns the currently active system configuration.
    Useful for deployment verification and debugging.
    Does not expose API keys or secrets.
    """
    from db.repositories.settings import SettingsRepository

    repo              = SettingsRepository(db)
    stored_thresholds = await repo.get("policy_thresholds") or {}
    stored_layers     = await repo.get("detection_layers")  or {}
    stored_llm        = await repo.get("llm_settings")      or {}

    return {
        "version": settings.app_version,
        "thresholds": {
            "block":    stored_thresholds.get("block_threshold",    settings.block_threshold),
            "sanitize": stored_thresholds.get("sanitize_threshold", settings.sanitize_threshold),
            "source":   "database" if stored_thresholds else "environment",
        },
        "detection_layers": {
            "rule":   stored_layers.get("rule_enabled", True),
            "ml":     stored_layers.get("ml_enabled",   True),
            "llm":    stored_layers.get("llm_enabled",  True),
            "source": "database" if stored_layers else "environment",
        },
        "llm": {
            "provider":    stored_llm.get("provider",    settings.llm_provider),
            "model":       stored_llm.get("model",       settings.llm_model),
            "llm_trigger": stored_llm.get("llm_trigger", settings.llm_trigger_threshold),
            "timeout":     stored_llm.get("timeout",     settings.llm_timeout),
            "source":      "database" if stored_llm else "environment",
        },
        "rate_limit": {
            "per_minute": 60,
            "scope":      "per_api_key",
        },
    }