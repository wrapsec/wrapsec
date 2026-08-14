# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal, require_admin
from api.v1.dependencies.db import get_db
from db.repositories.tenant import TenantRepository
from domain.entities.principal import Principal
from services.localization import validate_locale_input
from services.time import parse_utc_iso, to_iso_z, utc_now

router = APIRouter()


async def _resolve_caller_tenant(repo: TenantRepository, request: Request):
    """Resolve the caller's OWN tenant from the authenticated identity.

    Every tenant-profile read/write is scoped to request.state.tenant_id -- never
    a fixed 'default' tenant -- so a tenant admin can only ever view or modify
    their own tenant, not a shared/other one.
    """
    tid = getattr(request.state, "tenant_id", None)
    if not tid:
        return None
    try:
        return await repo.get_by_id(uuid.UUID(str(tid)))
    except (ValueError, TypeError):
        return None


def _format(tenant, is_admin: bool = False) -> dict:
    return {
        "id":            str(tenant.id),
        "slug":          tenant.slug,
        "name":          tenant.name,
        "description":   tenant.description,
        "contact_email": tenant.contact_email,
        "status":        tenant.status,
        "created_at":    to_iso_z(tenant.created_at),
        "locale":        tenant.locale,
    }


class TenantUpdateSchema(BaseModel):
    name:          str                | None = None
    description:   str                | None = None
    contact_email: str                | None = None
    # Tenant default locale (BCP-47). Validated against the supported-locales
    # allowlist; an unsupported value is rejected 422 INVALID_ENUM. max_length
    # mirrors the tenants.locale VARCHAR(35) column and caps an oversized string
    # before the allowlist validator runs (same boundary as MePatchSchema).
    locale:        str                | None = Field(default=None, max_length=35)

    @field_validator("locale")
    @classmethod
    def _valid_locale(cls, v: str | None) -> str | None:
        return validate_locale_input(v)


@router.get("")
async def get_tenant(
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Returns the caller's tenant profile (metadata + lifecycle status).
    Scoped to the caller's own tenant. Auth: any valid principal.
    """
    repo   = TenantRepository(db)
    tenant = await _resolve_caller_tenant(repo, request)
    if not tenant:
        return JSONResponse(content={"error": "No tenant found"}, status_code=404)
    return JSONResponse(content=_format(tenant, is_admin=getattr(_principal, "is_admin", False)))


@router.put("")
async def update_tenant(
    body:      TenantUpdateSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    _principal: Principal   = Depends(require_admin()),
):
    """
    Partially updates tenant metadata: name, description, contact_email, locale.
    Only fields present in the request body are updated. Scoped to the caller's
    own tenant. Auth: JWT + ADMIN role required.
    """
    repo   = TenantRepository(db)
    tenant = await _resolve_caller_tenant(repo, request)
    if not tenant:
        return JSONResponse(content={"error": "No tenant found"}, status_code=404)

    if body.name          is not None: tenant.name          = body.name
    if body.description   is not None: tenant.description   = body.description
    if body.contact_email is not None: tenant.contact_email = body.contact_email
    if body.locale        is not None: tenant.locale        = body.locale

    await db.commit()
    await db.refresh(tenant)
    return JSONResponse(content=_format(tenant, is_admin=True))

@router.get("/usage")
async def tenant_usage(
    request:    Request,
    from_:      str | None   = Query(None, alias="from"),
    to:         str | None   = Query(None, alias="to"),
    db:         AsyncSession  = Depends(get_db),
    _principal: Principal     = Depends(get_current_principal),
):
    """
    Tenant-scoped usage aggregate over audit_logs: scan/proxy request counts and
    blocked/sanitized decisions, totalled and broken down by day, for the caller's
    tenant. The metering contract for a future billing plugin, proven while cheap --
    it rests on every request path (scan/batch/proxy/cache-hit) writing an audit row.
    Window is [from, to); defaults to the last 30 days. Scoped to request.state.tenant_id.
    """
    tid = getattr(request.state, "tenant_id", None)
    if not tid:
        return JSONResponse(status_code=404, content={"error": "No tenant found"})

    try:
        end   = parse_utc_iso(to) if to else utc_now()
        start = parse_utc_iso(from_) if from_ else end - timedelta(days=30)
    except (ValueError, TypeError):
        return JSONResponse(status_code=400, content={
            "error": {"code": "INVALID_REQUEST", "message": "from/to must be ISO-8601 timestamps."}})
    if start >= end:
        return JSONResponse(status_code=400, content={
            "error": {"code": "INVALID_REQUEST", "message": "'from' must be before 'to'."}})

    rows = (await db.execute(text(
        "SELECT date_trunc('day', created_at) AS day, execution_mode AS mode, "
        "       decision AS decision, COUNT(*) AS n "
        "FROM audit_logs "
        "WHERE tenant_id = :tid AND created_at >= :start AND created_at < :end "
        "GROUP BY day, execution_mode, decision"
    ), {"tid": str(tid), "start": start, "end": end})).all()

    by_day: dict[str, dict] = {}
    totals = {"scan": 0, "proxy": 0, "blocked": 0, "sanitized": 0, "total": 0}
    for day, mode, decision, n in rows:
        key    = to_iso_z(day)[:10]
        bucket = by_day.setdefault(
            key, {"day": key, "scan": 0, "proxy": 0, "blocked": 0, "sanitized": 0, "total": 0})
        n = int(n)
        bucket["total"] += n; totals["total"] += n
        if mode == "proxy":
            bucket["proxy"] += n; totals["proxy"] += n
        else:
            bucket["scan"] += n;  totals["scan"] += n
        if decision == "BLOCK":
            bucket["blocked"] += n; totals["blocked"] += n
        elif decision == "SANITIZE":
            bucket["sanitized"] += n; totals["sanitized"] += n

    return JSONResponse(content={
        "from":   to_iso_z(start),
        "to":     to_iso_z(end),
        "totals": totals,
        "by_day": [by_day[k] for k in sorted(by_day)],
    })
