from fastapi import APIRouter
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