# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec reference plugin (refplugin).

A deliberately trivial plugin whose only job is to exercise every open-core seam
so the plugin/SaaS strategy is validated by construction rather than assumed. It
is a permanent TEST INSTRUMENT, not a product feature.
See docs/internal/saas_plugin_strategy.md section 6.

Increment 1 (this module): register one capability and one authenticated,
self-gating route -- the minimum that proves plugin discovery, registration,
auth-middleware passthrough, and the capability-ceiling self-gating contract.

Dependency discipline (strategy P1/P2/P3):
  - This package imports core; core never imports it.
  - register() is additive only: it mounts a NEW router and registers a NEW
    capability. It never patches or replaces a core component.
"""

# NOTE (plugin contract gotcha): do NOT add `from __future__ import annotations`
# here. Route handlers are defined inside register() with imports local to that
# function; PEP 563 string annotations would leave FastAPI's get_type_hints
# unable to resolve `Request`/`Principal` against register()'s local scope, and
# it would treat `request` as a required query param (HTTP 422). Real
# annotations resolve at def-time from the enclosing scope. This belongs in
# PLUGIN_CONTRACT.md.

CAPABILITY = "ref.ping"


def register(app) -> None:
    """Entry point called by services.capabilities.load_plugins at startup."""
    from fastapi import APIRouter, Depends, Request
    from fastapi.responses import JSONResponse

    from api.v1.dependencies.auth import get_current_principal
    from domain.entities.principal import Principal
    from services.capabilities import capability_available, register_capability

    register_capability(CAPABILITY)

    router = APIRouter()

    @router.get("/v1/ref/ping")
    async def ref_ping(
        request:    Request,
        _principal: Principal = Depends(get_current_principal),
    ) -> JSONResponse:
        # Cardinal rule: the capability registration is INFORMATIONAL, never
        # authorization. The route self-gates on capability availability at
        # request time (in SaaS it would also check the caller's tenant
        # entitlement here). This is the pattern every real feature copies.
        if not capability_available(CAPABILITY):
            return JSONResponse(
                status_code=404,
                content={"error": {"code": "NOT_FOUND", "message": f"{CAPABILITY} not available"}},
            )
        return JSONResponse(content={
            "pong":       True,
            "capability": CAPABILITY,
            "tenant_id":  getattr(request.state, "tenant_id", None),
        })

    app.include_router(router)
