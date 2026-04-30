# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.db import get_db
from db.repositories.application import ApplicationRepository
from db.repositories.department import DepartmentRepository
from db.repositories.tenant import TenantRepository
from errors.exceptions import NotFoundError
from pydantic import BaseModel

router = APIRouter()


def _format(app) -> dict:
    return {
        "id":                   str(app.id),
        "tenant_id":            str(app.tenant_id),
        "dept_id":              str(app.dept_id),
        "slug":                 app.slug,
        "name":                 app.name,
        "description":          app.description,
        "owner_name":           app.owner_name,
        "owner_email":          app.owner_email,
        "environment":          app.environment,
        "metadata":             app.metadata_,
        "policy_override":      app.policy_override,
        "rate_limit_override":  app.rate_limit_override,
        "is_active":            app.is_active,
        "created_at":           app.created_at.isoformat(),
    }


class ApplicationCreateSchema(BaseModel):
    dept_id:            str
    slug:               str
    name:               str
    description:        str  | None = None
    owner_name:         str  | None = None
    owner_email:        str  | None = None
    environment:        str  | None = "production"
    metadata:           dict | None = None
    policy_override:    dict | None = None
    rate_limit_override: int | None = None


class ApplicationUpdateSchema(BaseModel):
    name:               str  | None = None
    description:        str  | None = None
    owner_name:         str  | None = None
    owner_email:        str  | None = None
    environment:        str  | None = None
    metadata:           dict | None = None
    policy_override:    dict | None = None
    rate_limit_override: int | None = None
    is_active:          bool | None = None


@router.post("")
async def create_application(
    body: ApplicationCreateSchema,
    db:   AsyncSession = Depends(get_db),
):
    tenant_repo = TenantRepository(db)
    tenant      = await tenant_repo.get_default()

    # Validate department belongs to tenant
    dept_repo = DepartmentRepository(db)
    dept      = await dept_repo.get_by_id(uuid.UUID(body.dept_id))
    if not dept or str(dept.tenant_id) != str(tenant.id):
        raise NotFoundError("department", body.dept_id)

    repo   = ApplicationRepository(db)
    record = await repo.create({
        "tenant_id":           tenant.id,
        "dept_id":             uuid.UUID(body.dept_id),
        "slug":                body.slug,
        "name":                body.name,
        "description":         body.description,
        "owner_name":          body.owner_name,
        "owner_email":         body.owner_email,
        "environment":         body.environment or "production",
        "metadata_":           body.metadata,
        "policy_override":     body.policy_override,
        "rate_limit_override": body.rate_limit_override,
    })
    return JSONResponse(content=_format(record), status_code=201)


@router.get("")
async def list_applications(
    dept_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    tenant_repo = TenantRepository(db)
    tenant      = await tenant_repo.get_default()
    repo        = ApplicationRepository(db)

    if dept_id:
        items = await repo.list_by_dept(uuid.UUID(dept_id))
    else:
        items = await repo.list_by_tenant(tenant.id)

    return JSONResponse(content={"applications": [_format(a) for a in items]})


@router.get("/{app_id}")
async def get_application(app_id: str, db: AsyncSession = Depends(get_db)):
    repo   = ApplicationRepository(db)
    record = await repo.get_by_id(uuid.UUID(app_id))
    if not record:
        raise NotFoundError("application", app_id)
    return JSONResponse(content=_format(record))


@router.put("/{app_id}")
async def update_application(
    app_id: str,
    body:   ApplicationUpdateSchema,
    db:     AsyncSession = Depends(get_db),
):
    repo = ApplicationRepository(db)
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    if "metadata" in data:
        data["metadata_"] = data.pop("metadata")
    record = await repo.update(uuid.UUID(app_id), data)
    if not record:
        raise NotFoundError("application", app_id)
    return JSONResponse(content=_format(record))


@router.delete("/{app_id}")
async def delete_application(app_id: str, db: AsyncSession = Depends(get_db)):
    repo   = ApplicationRepository(db)
    record = await repo.update(uuid.UUID(app_id), {"is_active": False})
    if not record:
        raise NotFoundError("application", app_id)
    return JSONResponse(content={"app_id": app_id, "deactivated": True})

@router.get("/{app_id}/policy")
async def get_application_policy(
    app_id: str,
    db:     AsyncSession = Depends(get_db),
):
    """
    Returns the fully resolved effective policy for this application.
    Merges: system defaults → tenant global → department → application.
    Application overrides are null in v1 — will be active in v1.1.
    """
    from services.policy_resolver import resolve_policy
    import uuid as uuid_lib

    repo = ApplicationRepository(db)
    app  = await repo.get_by_id(uuid_lib.UUID(app_id))
    if not app:
        raise NotFoundError("application", app_id)

    policy, policy_source = await resolve_policy(
        db        = db,
        tenant_id = str(app.tenant_id),
        dept_id   = str(app.dept_id),
        app_id    = app_id,
    )

    return JSONResponse(content={
        "app_id":          app_id,
        "app_name":        app.name,
        "dept_id":         str(app.dept_id),
        "policy_source":   policy_source,
        "override_set":    app.policy_override is not None,
        "policy_override": app.policy_override,  # null in v1
        "resolved_policy": policy,
    })

class ApplicationPolicySchema(BaseModel):
    policy_override: dict | None = None


@router.put("/{app_id}/policy")
async def set_application_policy(
    app_id: str,
    body:   ApplicationPolicySchema,
    db:     AsyncSession = Depends(get_db),
):
    """
    Set or update application-level policy override.
    Merged on top of department policy during request processing.
    Pass policy_override: null to remove all overrides.
    """
    repo   = ApplicationRepository(db)
    record = await repo.get_by_id(uuid.UUID(app_id))
    if not record:
        raise NotFoundError("application", app_id)

    record = await repo.update(uuid.UUID(app_id), {
        "policy_override": body.policy_override
    })

    from services.policy_resolver import resolve_policy
    policy, policy_source = await resolve_policy(
        db        = db,
        tenant_id = str(record.tenant_id),
        dept_id   = str(record.dept_id),
        app_id    = app_id,
    )

    return JSONResponse(content={
        "app_id":          app_id,
        "app_name":        record.name,
        "dept_id":         str(record.dept_id),
        "policy_override": record.policy_override,
        "policy_source":   policy_source,
        "resolved_policy": policy,
        "updated":         True,
    })


@router.delete("/{app_id}/policy")
async def reset_application_policy(
    app_id: str,
    db:     AsyncSession = Depends(get_db),
):
    """
    Reset application policy override to null.
    Application will inherit from department policy.
    """
    repo   = ApplicationRepository(db)
    record = await repo.get_by_id(uuid.UUID(app_id))
    if not record:
        raise NotFoundError("application", app_id)

    await repo.update(uuid.UUID(app_id), {"policy_override": None})

    return JSONResponse(content={
        "app_id":          app_id,
        "app_name":        record.name,
        "policy_override": None,
        "reset":           True,
        "message":         "Application policy override removed. Inheriting from department.",
    })