# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from fastapi import APIRouter

from api.v1.endpoints import (
    agent_runs,
    ai,
    applications,
    audit,
    auth,
    capabilities,
    departments,
    health,
    keys,
    proxy,
    proxy_interactions,
    proxy_settings,
    settings,
    setup,
    tenant,
    webhooks,
)
from api.v1.endpoints.admin import email as admin_email
from api.v1.endpoints.admin import tenants as admin_tenants
from api.v1.endpoints.admin import users

router = APIRouter()

# THE PUBLISHED SCHEMA IS THE INTEGRATOR API, NOT THE ROUTE TABLE.
#
# `docs/openapi.json` describes the surface an SDK, the protocol adapter or a
# documented integration calls. Operator, dashboard-only and first-run routes
# stay served and stay authorized exactly as before -- `include_in_schema=False`
# hides a route from the schema and from /docs, and changes nothing about
# routing, authentication or behaviour. It is documentation scope, never an
# access control: never rely on it to keep a caller out of an endpoint.
#
# Whole routers are marked here so the boundary is legible in one place. The four
# routers that are only PARTLY public (audit, keys, settings, proxy settings)
# carry the flag on the individual routes instead; each says why.
#
# `tests/unit/test_openapi_contract.py` holds the resulting boundary exactly: it
# fails both if a public route stops being published and if anything else starts.

router.include_router(health.router,              tags=["Health"])
router.include_router(capabilities.router,        tags=["Capabilities"])
router.include_router(ai.router,                  prefix="/v1/ai",                 tags=["Gateway"])
router.include_router(audit.router,               prefix="/v1/audit",              tags=["Audit"])
router.include_router(agent_runs.router,          prefix="/v1/agent-runs",         tags=["Agent Runs"])
router.include_router(settings.router,            prefix="/v1/settings",           tags=["Settings"])
router.include_router(keys.router,                prefix="/v1/keys",               tags=["API Keys"])
router.include_router(tenant.router,              prefix="/v1/admin/tenant",       tags=["Tenant"],
                      include_in_schema=False)      # tenant self-administration, dashboard only
router.include_router(departments.router,         prefix="/v1/admin/departments",  tags=["Departments"],
                      include_in_schema=False)      # org structure, dashboard only
router.include_router(applications.router,        prefix="/v1/admin/applications", tags=["Applications"],
                      include_in_schema=False)      # org structure, dashboard only
router.include_router(webhooks.router,            prefix="/v1/admin/webhooks",     tags=["Webhooks"],
                      include_in_schema=False)      # outbound delivery config, dashboard only
router.include_router(proxy_settings.router,      prefix="/v1/settings",           tags=["Proxy"])
router.include_router(proxy.router,               prefix="/v1",                    tags=["Proxy"])
router.include_router(proxy_interactions.router,  prefix="/v1/proxy",              tags=["Proxy"])

# ── JWT Auth ───────────────────────────────────────────────────────────────────
router.include_router(auth.router,                prefix="/v1/auth",               tags=["Auth"],
                      include_in_schema=False)      # human session flow; integrators authenticate with an API key
router.include_router(users.router,               prefix="/v1/admin/users",        tags=["Users"],
                      include_in_schema=False)      # membership administration, dashboard only
router.include_router(admin_email.router,          prefix="/v1/admin/email",        tags=["Email Audit"],
                      include_in_schema=False)      # deployment mail settings and outbox, dashboard only
router.include_router(admin_tenants.router,        prefix="/v1/admin/tenants",      tags=["Platform"])

# ── First-run setup ────────────────────────────────────────────────────────────
router.include_router(setup.router,               prefix="/v1/setup",              tags=["Setup"])
