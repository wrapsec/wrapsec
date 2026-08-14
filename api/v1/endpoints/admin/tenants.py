# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Platform-operator tenant provisioning (control plane).

Every endpoint here is gated by require_platform_operator() -- cross-tenant
authority held today by the admin API key sentinel (key:admin), not by any tenant
ADMIN user. Actions are logged structurally (admin_events is for tenant-scoped user
actions and cannot represent a no-tenant operator). Hidden from the public schema.
"""
import logging
import re
import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import require_platform_operator
from api.v1.dependencies.db import get_db
from db.repositories.membership import MembershipRepository
from db.repositories.tenant import TenantRepository
from db.repositories.user import UserRepository
from domain.entities.principal import Principal
from errors.exceptions import NotFoundError
from services.auth.password import (
    hash_password,
    normalize_email,
    validate_password_strength,
)
from services.time import to_iso_z

router = APIRouter()
logger = logging.getLogger("wrapsec.platform.tenants")

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,49}$")


def _format(tenant) -> dict:
    return {
        "id":           str(tenant.id),
        "slug":         tenant.slug,
        "name":         tenant.name,
        "description":  tenant.description,
        "status":       tenant.status,
        "plan":         tenant.plan,
        "suspended_at": to_iso_z(tenant.suspended_at) if tenant.suspended_at else None,
        "created_at":   to_iso_z(tenant.created_at),
    }


def _bad_request(message: str) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": {"code": "INVALID_REQUEST", "message": message}})


class TenantCreateSchema(BaseModel):
    slug:        str
    name:        str         = Field(min_length=1, max_length=100)
    description: str | None  = Field(default=None, max_length=500)


class BootstrapAdminSchema(BaseModel):
    email:    EmailStr
    password: str


@router.post("", include_in_schema=False)
async def create_tenant(
    body:      TenantCreateSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    operator:  Principal    = Depends(require_platform_operator()),
) -> JSONResponse:
    slug = body.slug.strip().lower()
    if not _SLUG_RE.match(slug):
        return _bad_request("slug must be 2-50 chars, lowercase alphanumeric or hyphen, starting alphanumeric.")

    try:
        tenant = await TenantRepository(db).create(
            slug=slug, name=body.name, description=body.description, created_by=operator.id,
        )
        await db.commit()
    except ValueError as e:
        return JSONResponse(status_code=409, content={"error": {"code": "CONFLICT", "message": str(e)}})

    logger.info("platform_event TENANT_CREATED operator=%s tenant_id=%s slug=%s",
                operator.id, tenant.id, tenant.slug)
    return JSONResponse(status_code=201, content=_format(tenant))


@router.get("", include_in_schema=False)
async def list_tenants(
    _operator: Principal    = Depends(require_platform_operator()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    tenants = await TenantRepository(db).list_all()
    return JSONResponse(content={"total": len(tenants), "tenants": [_format(t) for t in tenants]})


@router.get("/{tenant_id}", include_in_schema=False)
async def get_tenant(
    tenant_id: uuid.UUID,
    _operator: Principal    = Depends(require_platform_operator()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    tenant = await TenantRepository(db).get_by_id(tenant_id)
    if tenant is None:
        raise NotFoundError("tenant", str(tenant_id))
    return JSONResponse(content=_format(tenant))


async def _set_status(tenant_id: uuid.UUID, status: str, operator: Principal, db: AsyncSession) -> JSONResponse:
    repo   = TenantRepository(db)
    tenant = await repo.set_status(tenant_id, status)
    if tenant is None:
        raise NotFoundError("tenant", str(tenant_id))
    await db.commit()
    logger.info("platform_event TENANT_%s operator=%s tenant_id=%s",
                status.upper(), operator.id, tenant_id)
    return JSONResponse(content=_format(tenant))


@router.post("/{tenant_id}/suspend", include_in_schema=False)
async def suspend_tenant(
    tenant_id: uuid.UUID,
    operator:  Principal    = Depends(require_platform_operator()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    return await _set_status(tenant_id, "suspended", operator, db)


@router.post("/{tenant_id}/reactivate", include_in_schema=False)
async def reactivate_tenant(
    tenant_id: uuid.UUID,
    operator:  Principal    = Depends(require_platform_operator()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    return await _set_status(tenant_id, "active", operator, db)


@router.post("/{tenant_id}/bootstrap-admin", include_in_schema=False)
async def bootstrap_admin(
    tenant_id: uuid.UUID,
    body:      BootstrapAdminSchema,
    request:   Request,
    operator:  Principal    = Depends(require_platform_operator()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Create the FIRST admin user of a tenant (its identity + ADMIN membership).
    Refuses once the tenant already has any membership."""
    tenant_repo = TenantRepository(db)
    tenant      = await tenant_repo.get_by_id(tenant_id)
    if tenant is None:
        raise NotFoundError("tenant", str(tenant_id))

    mem_repo = MembershipRepository(db)
    if await mem_repo.count_in_tenant(tenant_id) > 0:
        return JSONResponse(status_code=409, content={
            "error": {"code": "CONFLICT", "message": "Tenant already has members; bootstrap is first-admin only."}
        })

    email = normalize_email(str(body.email))
    try:
        validate_password_strength(body.password)
    except ValueError as e:
        return _bad_request(str(e))

    user_repo = UserRepository(db)
    if await user_repo.get_by_email(email):
        return JSONResponse(status_code=409, content={
            "error": {"code": "CONFLICT", "message": "A user with this email already exists."}
        })

    user = await user_repo.create({
        "email":                 email,
        "password_hash":         hash_password(body.password),
        "force_password_change": True,
    })
    await user_repo.flush()
    await mem_repo.upsert_for_user(user_id=user.id, tenant_id=tenant_id, role="ADMIN", dept_id=None)
    await db.commit()

    logger.info("platform_event TENANT_ADMIN_BOOTSTRAPPED operator=%s tenant_id=%s user_id=%s",
                operator.id, tenant_id, user.id)
    return JSONResponse(status_code=201, content={"id": str(user.id), "email": user.email, "role": "ADMIN"})
