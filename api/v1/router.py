# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from fastapi import APIRouter
from api.v1.endpoints import (
    health, ai, audit, settings, keys,
    departments, applications, tenant,
    proxy_settings, proxy,
    auth, setup,
)
from api.v1.endpoints.admin import users

router = APIRouter()

router.include_router(health.router,              tags=["Health"])
router.include_router(ai.router,                  prefix="/v1/ai",                 tags=["Gateway"])
router.include_router(audit.router,               prefix="/v1/audit",              tags=["Audit"])
router.include_router(settings.router,            prefix="/v1/settings",           tags=["Settings"])
router.include_router(keys.router,                prefix="/v1/keys",               tags=["API Keys"])
router.include_router(tenant.router,              prefix="/v1/admin/tenant",       tags=["Tenant"])
router.include_router(departments.router,         prefix="/v1/admin/departments",  tags=["Departments"])
router.include_router(applications.router,        prefix="/v1/admin/applications", tags=["Applications"])
router.include_router(proxy_settings.router,      prefix="/v1/settings",           tags=["Proxy"])
router.include_router(proxy.router,               prefix="/v1",                    tags=["Proxy"])

# ── JWT Auth ───────────────────────────────────────────────────────────────────
router.include_router(auth.router,                prefix="/v1/auth",               tags=["Auth"])
router.include_router(users.router,               prefix="/v1/admin/users",        tags=["Users"])

# ── First-run setup ────────────────────────────────────────────────────────────
router.include_router(setup.router,               prefix="/v1/setup",              tags=["Setup"])
