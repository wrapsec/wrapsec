from fastapi import APIRouter
from api.v1.endpoints import health, ai, audit, settings, keys, departments, applications, tenant, proxy_settings, proxy

router = APIRouter()

router.include_router(health.router,        tags=["Health"])
router.include_router(ai.router,            prefix="/v1/ai",                tags=["Gateway"])
router.include_router(audit.router,         prefix="/v1/audit",             tags=["Audit"])
router.include_router(settings.router,      prefix="/v1/settings",          tags=["Settings"])
router.include_router(keys.router,          prefix="/v1/keys",              tags=["API Keys"])
router.include_router(tenant.router,        prefix="/v1/admin/tenant",      tags=["Tenant"])
router.include_router(departments.router,   prefix="/v1/admin/departments",  tags=["Departments"])
router.include_router(applications.router,  prefix="/v1/admin/applications", tags=["Applications"])
router.include_router(proxy_settings.router, prefix="/v1/settings", tags=["Proxy"])
router.include_router(proxy.router,         prefix="/v1",                   tags=["Proxy"])