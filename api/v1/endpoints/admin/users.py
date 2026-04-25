import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import require_admin
from api.v1.dependencies.db import get_db
from domain.entities.principal import Principal
from errors.exceptions import NotFoundError
from services.auth.service import AuthService

router = APIRouter()

auth_service = AuthService()


# ── Formatters ─────────────────────────────────────────────────────────────────

def _format(user) -> dict:
    return {
        "id":                    str(user.id),
        "email":                 user.email,
        "role":                  user.role,
        "dept_id":               str(user.dept_id)   if user.dept_id   else None,
        "tenant_id":             str(user.tenant_id) if user.tenant_id else None,
        "is_active":             user.is_active,
        "force_password_change": user.force_password_change,
        "created_at":            user.created_at.isoformat(),
        "last_login_at":         user.last_login_at.isoformat() if user.last_login_at else None,
    }


# ── Schemas ────────────────────────────────────────────────────────────────────

class UserCreateSchema(BaseModel):
    email:    EmailStr
    password: str
    role:     str           # ADMIN | DEVELOPER | VIEWER
    dept_id:  str | None = None   # required for DEVELOPER/VIEWER, absent for ADMIN


class UserUpdateSchema(BaseModel):
    role:      str  | None = None
    dept_id:   str  | None = None
    is_active: bool | None = None


class ResetPasswordSchema(BaseModel):
    new_password: str


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("")
async def create_user(
    body:      UserCreateSchema,
    request:   Request,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Creates a new dashboard user.
    force_password_change = True is set automatically.
    User must change password on first login.

    Auth: JWT + ADMIN role required.

    Errors:
        400 INVALID_REQUEST — weak password, invalid role, missing dept_id,
                              dept from different tenant
        409 CONFLICT        — email already registered
    """
    from db.repositories.user import UserRepository
    from services.auth.password import (
        hash_password, normalize_email, validate_password_strength,
    )

    email = normalize_email(str(body.email))

    try:
        validate_password_strength(body.password)
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": str(e)}},
        )

    repo = UserRepository(db)

    # Check email uniqueness
    existing = await repo.get_by_email(email)
    if existing:
        return JSONResponse(
            status_code=409,
            content={"error": {
                "code":    "CONFLICT",
                "message": "A user with this email already exists.",
            }},
        )

    try:
        user = await repo.create({
            "tenant_id":             uuid.UUID(str(principal.tenant_id)),
            "email":                 email,
            "password_hash":         hash_password(body.password),
            "role":                  body.role,
            "dept_id":               uuid.UUID(body.dept_id) if body.dept_id else None,
            "force_password_change": True,
        })
        await db.commit()
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": str(e)}},
        )

    return JSONResponse(status_code=201, content=_format(user))


@router.get("")
async def list_users(
    request:   Request,
    role:      str  | None = None,
    is_active: bool | None = None,
    limit:     int  = 50,
    offset:    int  = 0,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Lists all users for the tenant.
    Scoped to principal.tenant_id — never cross-tenant.

    Auth: JWT + ADMIN role required.
    """
    from db.repositories.user import UserRepository

    repo = UserRepository(db)
    users, total = await repo.list_by_tenant(
        tenant_id = uuid.UUID(str(principal.tenant_id)),
        role      = role,
        is_active = is_active,
        limit     = limit,
        offset    = offset,
    )

    return JSONResponse(content={
        "total": total,
        "users": [_format(u) for u in users],
    })


@router.get("/{user_id}")
async def get_user(
    user_id:   str,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Returns a single user by ID.
    Scoped to principal.tenant_id.

    Auth: JWT + ADMIN role required.
    """
    from db.repositories.user import UserRepository

    repo = UserRepository(db)
    user = await repo.get_by_id(uuid.UUID(user_id))

    if not user or str(user.tenant_id) != principal.tenant_id:
        raise NotFoundError("user", user_id)

    return JSONResponse(content=_format(user))


@router.put("/{user_id}")
async def update_user(
    user_id:   str,
    body:      UserUpdateSchema,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Updates user role, dept_id, or is_active.

    Pre-flight validation:
    - If demoting ADMIN role or deactivating ADMIN: checks last-admin protection
    - If changing dept_id: verifies dept belongs to same tenant

    Post-change side effects:
    - If role changed OR is_active=False: logout_all_sessions()

    Auth: JWT + ADMIN role required.
    """
    from db.repositories.user import UserRepository

    repo = UserRepository(db)
    user = await repo.get_by_id(uuid.UUID(user_id))

    if not user or str(user.tenant_id) != principal.tenant_id:
        raise NotFoundError("user", user_id)

    data = body.model_dump(exclude_unset=True)

    # Last-admin protection — check BEFORE making any changes
    new_role      = data.get("role")
    new_is_active = data.get("is_active")

    is_demoting_admin     = (user.role == "ADMIN" and new_role is not None and new_role != "ADMIN")
    is_deactivating_admin = (user.role == "ADMIN" and new_is_active is False)

    if is_demoting_admin or is_deactivating_admin:
        active_admins = await repo.count_active_admins(uuid.UUID(str(principal.tenant_id)))
        if active_admins <= 1:
            return JSONResponse(
                status_code=400,
                content={"error": {
                    "code":    "INVALID_REQUEST",
                    "message": "Cannot demote or deactivate the last active admin. "
                               "Create another admin first.",
                }},
            )

    # Convert dept_id to UUID if provided
    if "dept_id" in data and data["dept_id"] is not None:
        data["dept_id"] = uuid.UUID(data["dept_id"])

    try:
        updated = await repo.update(uuid.UUID(user_id), data)
        await db.commit()
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": str(e)}},
        )

    # Invalidate all sessions if role changed or account deactivated
    if new_role is not None or new_is_active is False:
        await auth_service.logout_all_sessions(uuid.UUID(user_id), db)

    return JSONResponse(content=_format(updated))


@router.post("/{user_id}/reset-password")
async def reset_password(
    user_id:   str,
    body:      ResetPasswordSchema,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Admin resets a user's password.
    Sets force_password_change = True automatically.
    Invalidates all active sessions.

    Auth: JWT + ADMIN role required.
    """
    from db.repositories.user import UserRepository
    from services.auth.password import hash_password, validate_password_strength

    repo = UserRepository(db)
    user = await repo.get_by_id(uuid.UUID(user_id))

    if not user or str(user.tenant_id) != principal.tenant_id:
        raise NotFoundError("user", user_id)

    try:
        validate_password_strength(body.new_password)
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": str(e)}},
        )

    await repo.update(uuid.UUID(user_id), {
        "password_hash":         hash_password(body.new_password),
        "force_password_change": True,
    })
    await db.commit()

    await auth_service.logout_all_sessions(uuid.UUID(user_id), db)

    return JSONResponse(content={
        "message": "Password reset. User must change password on next login.",
        "user_id": user_id,
    })
