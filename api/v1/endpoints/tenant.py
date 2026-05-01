# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from api.v1.dependencies.auth import get_current_principal, require_admin
from api.v1.dependencies.db import get_db
from db.repositories.tenant import TenantRepository
from domain.entities.principal import Principal

router = APIRouter()


def _format(tenant) -> dict:
    return {
        "id":            str(tenant.id),
        "slug":          tenant.slug,
        "name":          tenant.name,
        "description":   tenant.description,
        "global_policy": tenant.global_policy,
        "contact_email": tenant.contact_email,
        "is_active":     tenant.is_active,
        "created_at":    tenant.created_at.isoformat(),
    }


class TenantUpdateSchema(BaseModel):
    name:          str  | None = None
    description:   str  | None = None
    contact_email: str  | None = None
    global_policy: dict | None = None


@router.get("")
async def get_tenant(
    db:        AsyncSession = Depends(get_db),
    _principal: Principal   = Depends(get_current_principal),
):
    repo   = TenantRepository(db)
    tenant = await repo.get_default()
    if not tenant:
        return JSONResponse(content={"error": "No tenant found"}, status_code=404)
    return JSONResponse(content=_format(tenant))


@router.put("")
async def update_tenant(
    body:      TenantUpdateSchema,
    db:        AsyncSession = Depends(get_db),
    _principal: Principal   = Depends(require_admin()),
):
    repo   = TenantRepository(db)
    tenant = await repo.get_default()
    if not tenant:
        return JSONResponse(content={"error": "No tenant found"}, status_code=404)

    if body.name          is not None: tenant.name          = body.name
    if body.description   is not None: tenant.description   = body.description
    if body.contact_email is not None: tenant.contact_email = body.contact_email
    if body.global_policy is not None: tenant.global_policy = body.global_policy

    await db.commit()
    await db.refresh(tenant)
    return JSONResponse(content=_format(tenant))