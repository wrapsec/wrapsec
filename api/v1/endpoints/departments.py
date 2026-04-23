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


@router.get("/{dept_id}/stats")
async def get_department_stats(
    dept_id: str,
    db:      AsyncSession = Depends(get_db),
):
    from sqlalchemy import func
    from db.models import AuditLogModel
    from sqlalchemy import select as sa_select

    # Total requests
    total = await db.scalar(
        sa_select(func.count()).where(AuditLogModel.dept_id == dept_id)
    ) or 0

    # Decision breakdown
    decisions = await db.execute(
        sa_select(
            AuditLogModel.decision,
            func.count().label("count"),
        )
        .where(AuditLogModel.dept_id == dept_id)
        .group_by(AuditLogModel.decision)
    )
    decision_counts = {row.decision: row.count for row in decisions}

    # Average latency
    avg_latency = await db.scalar(
        sa_select(func.avg(AuditLogModel.latency_ms))
        .where(AuditLogModel.dept_id == dept_id)
    ) or 0.0

    # Top threats — aggregate in Python to avoid JSON/JSONB type issues
    threats_result = await db.execute(
        sa_select(AuditLogModel.threats)
        .where(AuditLogModel.dept_id == dept_id)
    )
    threat_counts: dict[str, int] = {}
    for row in threats_result:
        threats = row.threats or []
        if isinstance(threats, list):
            for t in threats:
                if t:
                    threat_counts[t] = threat_counts.get(t, 0) + 1

    top_threats = [
        {"category": k, "count": v}
        for k, v in sorted(
            threat_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
    ]

    block_rate = round(
        decision_counts.get("BLOCK", 0) / total, 3
    ) if total > 0 else 0.0

    return JSONResponse(content={
        "dept_id":        dept_id,
        "total":          total,
        "decisions":      decision_counts,
        "block_rate":     block_rate,
        "avg_latency_ms": round(avg_latency, 2),
        "top_threats":    top_threats,
    })

@router.get("/{dept_id}/policy")
async def get_department_policy(
    dept_id: str,
    db:      AsyncSession = Depends(get_db),
):
    """
    Returns the fully resolved effective policy for this department.
    Merges: system defaults → tenant global → department override.
    Useful for compliance verification.
    """
    from services.policy_resolver import resolve_policy

    repo   = DepartmentRepository(db)
    dept   = await repo.get_by_id(uuid.UUID(dept_id))
    if not dept:
        raise NotFoundError("department", dept_id)

    policy, policy_source = await resolve_policy(
        db        = db,
        tenant_id = str(dept.tenant_id),
        dept_id   = dept_id,
        app_id    = None,
    )

    return JSONResponse(content={
        "dept_id":       dept_id,
        "dept_name":     dept.name,
        "policy_source": policy_source,
        "override_set":  dept.policy_override is not None,
        "policy_override": dept.policy_override,
        "resolved_policy": policy,
    })

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
    # Use exclude_unset=True so explicitly set null values (e.g. policy_override=null)
    # are included — filtering "if v is not None" would silently drop them
    data = body.model_dump(exclude_unset=True)
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
