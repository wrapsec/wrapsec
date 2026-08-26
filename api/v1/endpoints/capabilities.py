# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
GET /v1/capabilities -- which optional plugin capabilities are EFFECTIVE in this
deployment (registered AND permitted by the WRAPSEC_FEATURES ceiling), so the
dashboard can show or hide the corresponding UI. Informational only: this
endpoint is NEVER an authorization control. The OSS edition returns an empty set;
the enterprise package registers capabilities as it wires licensed features in.
`edition` is descriptive display metadata, not an authorization claim.
"""

from typing import Any

from fastapi import APIRouter, Depends

from api.v1.dependencies.auth import get_current_principal
from api.v1.schemas.response import CapabilitiesResponse, ErrorEnvelope
from domain.entities.principal import Principal
from services.capabilities import effective_capabilities

router = APIRouter()

# The route takes no parameters, so authentication is its only reachable failure.
_CAPABILITY_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Missing or invalid credentials."},
}


@router.get(
    "/v1/capabilities",
    response_model               = CapabilitiesResponse,
    response_model_exclude_unset = True,
    responses                    = _CAPABILITY_ERRORS,
)
async def list_capabilities(
    principal: Principal = Depends(get_current_principal),
):
    caps = effective_capabilities()
    # A value, not a JSONResponse: a Response object bypasses the model.
    return {
        "edition":      "enterprise" if caps else "oss",
        "capabilities": caps,
    }
