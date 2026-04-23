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
from datetime import timedelta

router = APIRouter()


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_api_key() -> str:
    return "wsk_live_" + secrets.token_urlsafe(32)


def generate_key_id() -> str:
    return "key_" + secrets.token_hex(6)


class CreateKeySchema(BaseModel):
    name:       str
    dept_id:    str | None = None  # dept-scoped key (no app required)
    app_id:     str | None = None  # app-scoped key (dept+tenant derived from app)
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
        # App-scoped key: derive dept + tenant from app
        app_repo = ApplicationRepository(db)
        app      = await app_repo.get_by_id(uuid.UUID(body.app_id))
        if not app:
            raise NotFoundError("application", body.app_id)
        app_id    = app.id
        dept_id   = app.dept_id
        tenant_id = app.tenant_id
    elif body.dept_id:
        # Dept-scoped key: derive tenant from dept
        dept_repo = DepartmentRepository(db)
        dept      = await dept_repo.get_by_id(uuid.UUID(body.dept_id))
        if not dept:
            raise NotFoundError("department", body.dept_id)
        dept_id   = dept.id
        tenant_id = dept.tenant_id
    else:
        # No scope specified — link to default tenant + department
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
    # Filter out keys whose grace period has expired
    now  = datetime.utcnow()
    keys = [k for k in keys if k.expires_at is None or k.expires_at > now]

    # Enrich with department and application names
    dept_repo  = DepartmentRepository(db)
    app_repo   = ApplicationRepository(db)
    dept_names: dict = {}
    app_names:  dict = {}
    for k in keys:
        if k.dept_id and str(k.dept_id) not in dept_names:
            try:
                dept = await dept_repo.get_by_id(k.dept_id)
                dept_names[str(k.dept_id)] = dept.name if dept else None
            except Exception:
                dept_names[str(k.dept_id)] = None
        if k.app_id and str(k.app_id) not in app_names:
            try:
                app = await app_repo.get_by_id(k.app_id)
                app_names[str(k.app_id)] = app.name if app else None
            except Exception:
                app_names[str(k.app_id)] = None

    return JSONResponse(content={
        "keys": [
            {
                "key_id":       k.key_id,
                "name":         k.name,
                "app_id":       str(k.app_id)  if k.app_id  else None,
                "dept_id":      str(k.dept_id) if k.dept_id else None,
                "dept_name":    dept_names.get(str(k.dept_id)) if k.dept_id else None,
                "app_name":     app_names.get(str(k.app_id))   if k.app_id  else None,
                "created_at":   k.created_at.isoformat(),
                "expires_at":   k.expires_at.isoformat() if k.expires_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            }
            for k in keys
        ]
    })

@router.get("/{key_id}")
async def get_key(
    key_id: str,
    db:     AsyncSession = Depends(get_db),
):
    repo   = ApiKeyRepository(db)
    record = await repo.get_by_key_id(key_id)
    if not record:
        raise NotFoundError("key", key_id)

    return JSONResponse(content={
        "key_id":       record.key_id,
        "name":         record.name,
        "app_id":       str(record.app_id)    if record.app_id    else None,
        "dept_id":      str(record.dept_id)   if record.dept_id   else None,
        "tenant_id":    str(record.tenant_id) if record.tenant_id else None,
        "is_admin":     record.is_admin,
        "revoked":      record.revoked,
        "created_at":   record.created_at.isoformat(),
        "expires_at":   record.expires_at.isoformat() if record.expires_at else None,
        "last_used_at": record.last_used_at.isoformat() if record.last_used_at else None,
    })

class UpdateKeySchema(BaseModel):
    name: str

@router.put("/{key_id}")
async def update_key(
    key_id: str,
    body:   UpdateKeySchema,
    db:     AsyncSession = Depends(get_db),
):
    repo   = ApiKeyRepository(db)
    record = await repo.get_by_key_id(key_id)
    if not record:
        raise NotFoundError("key", key_id)

    record.name = body.name
    await db.commit()

    return JSONResponse(content={
        "key_id":     record.key_id,
        "name":       record.name,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })

@router.delete("/{key_id}")
async def delete_key(
    key_id: str,
    db:     AsyncSession = Depends(get_db),
):
    repo   = ApiKeyRepository(db)
    record = await repo.get_by_key_id(key_id)
    if not record:
        raise NotFoundError("key", key_id)

    was_in_grace = record.expires_at is not None and not record.revoked

    await repo.revoke(key_id)

    return JSONResponse(content={
        "key_id":          key_id,
        "revoked":         True,
        "revoked_at":      datetime.now(timezone.utc).isoformat(),
        "was_in_grace":    was_in_grace,
        "warning":         (
            "Key was in grace period and has been immediately revoked. "
            "Integrations using the old key will stop working now."
        ) if was_in_grace else None,
    })

class RotateKeySchema(BaseModel):
    grace_period_minutes: int = 60


@router.post("/{key_id}/rotate")
async def rotate_key(
    key_id: str,
    body:   RotateKeySchema,
    db:     AsyncSession = Depends(get_db),
):
    """
    Rotate an API key — generates a new secret while preserving all metadata.
    Old key remains valid for grace_period_minutes to allow graceful migration.
    After grace period, old key is automatically revoked.

    Returns the new key secret — shown once, store securely.
    """
    repo   = ApiKeyRepository(db)
    record = await repo.get_by_key_id(key_id)
    if not record:
        raise NotFoundError("key", key_id)
    if record.revoked:
        return JSONResponse(
            content={"error": {"code": "KEY_REVOKED", "message": "Cannot rotate a revoked key."}},
            status_code=400,
        )

    if record.expires_at is not None:
        now = datetime.utcnow()
        if record.expires_at > now:
            # Still in grace period
            return JSONResponse(
                content={"error": {"code": "KEY_IN_GRACE_PERIOD", "message": (
                    f"This key has already been rotated and is in its grace period "
                    f"(expires at {record.expires_at.isoformat()}). "
                    f"Use the new key for further rotations."
                )}},
                status_code=400,
            )
        else:
            # Grace period expired — key is effectively dead
            return JSONResponse(
                content={"error": {"code": "KEY_EXPIRED", "message": (
                    "This key's grace period has expired and it is no longer valid. "
                    "Use the new key that was created when this key was rotated."
                )}},
                status_code=400,
            )

    # Generate new key
    new_api_key = generate_api_key()
    new_key_id  = generate_key_id()
    new_hash    = _hash_key(new_api_key)

    # Calculate grace period expiry for old key
    # Strip timezone — DB column is TIMESTAMP WITHOUT TIME ZONE
    grace_expires = (datetime.now(timezone.utc) + timedelta(minutes=body.grace_period_minutes)).replace(tzinfo=None)

    # Create new key with same metadata
    new_record = await repo.create({
        "key_id":    new_key_id,
        "name":      record.name,
        "key_hash":  new_hash,
        "is_admin":  record.is_admin,
        "revoked":   False,
        "app_id":    record.app_id,
        "dept_id":   record.dept_id,
        "tenant_id": record.tenant_id,
    })

    # Set old key to expire at end of grace period
    record.expires_at = grace_expires
    await db.commit()

    return JSONResponse(content={
        "new_key_id":       new_key_id,
        "new_api_key":      new_api_key,
        "old_key_id":       key_id,
        "old_expires_at":   grace_expires.isoformat(),
        "grace_period_minutes": body.grace_period_minutes,
        "name":             record.name,
        "app_id":           str(record.app_id)    if record.app_id    else None,
        "dept_id":          str(record.dept_id)   if record.dept_id   else None,
        "created_at":       new_record.created_at.isoformat(),
        "message":          f"New key created. Old key expires in {body.grace_period_minutes} minutes.",
    }, status_code=201)