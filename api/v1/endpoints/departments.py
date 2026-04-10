import uuid
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.db import get_db
from db.repositories.department import DepartmentRepository
from db.repositories.tenant import TenantRepository
from errors.exceptions import NotFoundError
from pydantic import BaseModel

router = APIRouter()


def _format(dept) -> dict:
    return {
        "id":             str(dept.id),
        "tenant_id":      str(dept.tenant_id),
        "slug":           dept.slug,
        "name":           dept.name,
        "description":    dept.description,
        "policy_override": dept.policy_override,
        "contact_email":  dept.contact_email,
        "is_active":      dept.is_active,
        "created_at":     dept.created_at.isoformat(),
    }


class DepartmentCreateSchema(BaseModel):
    slug:            str
    name:            str
    description:     str | None = None
    policy_override: dict | None = None
    contact_email:   str | None = None


class DepartmentUpdateSchema(BaseModel):
    name:            str | None = None
    description:     str | None = None
    policy_override: dict | None = None
    contact_email:   str | None = None
    is_active:       bool | None = None


@router.post("")
async def create_department(
    body: DepartmentCreateSchema,
    db:   AsyncSession = Depends(get_db),
):
    tenant_repo = TenantRepository(db)
    tenant      = await tenant_repo.get_default()

    repo   = DepartmentRepository(db)
    record = await repo.create({
        "tenant_id":       tenant.id,
        "slug":            body.slug,
        "name":            body.name,
        "description":     body.description,
        "policy_override": body.policy_override,
        "contact_email":   body.contact_email,
    })
    return JSONResponse(content=_format(record), status_code=201)


@router.get("")
async def list_departments(db: AsyncSession = Depends(get_db)):
    tenant_repo = TenantRepository(db)
    tenant      = await tenant_repo.get_default()

    repo  = DepartmentRepository(db)
    items = await repo.list_by_tenant(tenant.id)
    return JSONResponse(content={"departments": [_format(d) for d in items]})


@router.get("/{dept_id}")
async def get_department(dept_id: str, db: AsyncSession = Depends(get_db)):
    repo   = DepartmentRepository(db)
    record = await repo.get_by_id(uuid.UUID(dept_id))
    if not record:
        raise NotFoundError("department", dept_id)
    return JSONResponse(content=_format(record))


@router.put("/{dept_id}")
async def update_department(
    dept_id: str,
    body:    DepartmentUpdateSchema,
    db:      AsyncSession = Depends(get_db),
):
    repo = DepartmentRepository(db)
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    record = await repo.update(uuid.UUID(dept_id), data)
    if not record:
        raise NotFoundError("department", dept_id)
    return JSONResponse(content=_format(record))


@router.delete("/{dept_id}")
async def delete_department(dept_id: str, db: AsyncSession = Depends(get_db)):
    repo   = DepartmentRepository(db)
    record = await repo.update(uuid.UUID(dept_id), {"is_active": False})
    if not record:
        raise NotFoundError("department", dept_id)
    return JSONResponse(content={"dept_id": dept_id, "deactivated": True})