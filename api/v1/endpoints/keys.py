import uuid
import secrets
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.db import get_db
from db.repositories.api_key import ApiKeyRepository
from db.repositories.application import ApplicationRepository
from db.repositories.department import DepartmentRepository
from db.repositories.tenant import TenantRepository
from errors.exceptions import NotFoundError

router = APIRouter()


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_api_key() -> str:
    return "wsk_live_" + secrets.token_urlsafe(32)


def generate_key_id() -> str:
    return "key_" + secrets.token_hex(6)


class CreateKeySchema(BaseModel):
    name:       str
    app_id:     str | None = None
    expires_at: str | None = None


@router.post("")
async def create_key(
    body: CreateKeySchema,
    db:   AsyncSession = Depends(get_db),
):
    api_key = generate_api_key()
    key_id  = generate_key_id()

    # Resolve app → dept → tenant chain
    app_id    = None
    dept_id   = None
    tenant_id = None

    if body.app_id:
        app_repo = ApplicationRepository(db)
        app      = await app_repo.get_by_id(uuid.UUID(body.app_id))
        if not app:
            raise NotFoundError("application", body.app_id)
        app_id    = app.id
        dept_id   = app.dept_id
        tenant_id = app.tenant_id
    else:
        # No app specified — link to default tenant + department
        tenant_repo = TenantRepository(db)
        dept_repo   = DepartmentRepository(db)
        tenant      = await tenant_repo.get_default()
        if tenant:
            dept = await dept_repo.get_default(tenant.id)
            tenant_id = tenant.id
            if dept:
                dept_id = dept.id

    repo   = ApiKeyRepository(db)
    record = await repo.create({
        "key_id":    key_id,
        "name":      body.name,
        "key_hash":  _hash_key(api_key),
        "is_admin":  False,
        "revoked":   False,
        "app_id":    app_id,
        "dept_id":   dept_id,
        "tenant_id": tenant_id,
    })

    return JSONResponse(content={
        "key_id":     key_id,
        "name":       body.name,
        "api_key":    api_key,
        "app_id":     str(app_id)    if app_id    else None,
        "dept_id":    str(dept_id)   if dept_id   else None,
        "tenant_id":  str(tenant_id) if tenant_id else None,
        "created_at": record.created_at.isoformat(),
        "expires_at": body.expires_at,
    }, status_code=201)


@router.get("")
async def list_keys(db: AsyncSession = Depends(get_db)):
    repo = ApiKeyRepository(db)
    keys = await repo.list_active()

    return JSONResponse(content={
        "keys": [
            {
                "key_id":       k.key_id,
                "name":         k.name,
                "app_id":       str(k.app_id)  if k.app_id  else None,
                "dept_id":      str(k.dept_id) if k.dept_id else None,
                "created_at":   k.created_at.isoformat(),
                "expires_at":   k.expires_at.isoformat() if k.expires_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            }
            for k in keys
        ]
    })


@router.delete("/{key_id}")
async def delete_key(
    key_id: str,
    db:     AsyncSession = Depends(get_db),
):
    repo   = ApiKeyRepository(db)
    record = await repo.revoke(key_id)

    if not record:
        raise NotFoundError("key", key_id)

    return JSONResponse(content={
        "key_id":     key_id,
        "revoked":    True,
        "revoked_at": datetime.now(timezone.utc).isoformat(),
    })