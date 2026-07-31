# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
GET /v1/capabilities -- which optional (paid) capabilities are active in this
deployment, so the dashboard can show or hide the corresponding UI. The OSS
edition returns an empty set; the enterprise package registers capabilities as
it wires licensed features in.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from api.v1.dependencies.auth import get_current_principal
from domain.entities.principal import Principal
from services.capabilities import get_capabilities

router = APIRouter()


@router.get("/v1/capabilities")
async def list_capabilities(
    principal: Principal = Depends(get_current_principal),
):
    caps = get_capabilities()
    return JSONResponse(content={
        "edition":      "enterprise" if caps else "oss",
        "capabilities": caps,
    })
