from fastapi import APIRouter
from api.v1.endpoints import health, ai, audit, settings, keys

router = APIRouter()

router.include_router(health.router,    tags=["Health"])
router.include_router(ai.router,        prefix="/v1/ai",      tags=["Gateway"])
router.include_router(audit.router,     prefix="/v1/audit",   tags=["Audit"])
router.include_router(settings.router,  prefix="/v1/settings",tags=["Settings"])
router.include_router(keys.router,      prefix="/v1/keys",    tags=["API Keys"])