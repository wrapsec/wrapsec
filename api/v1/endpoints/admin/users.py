# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import require_admin
from api.v1.dependencies.db import get_db
from domain.entities.principal import Principal
from domain.enums import AdminEventAction
from errors.exceptions import NotFoundError
from services.auth.service import AuthService

router = APIRouter()
logger = logging.getLogger("wrapsec.admin.users")

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


def _get_client_info(request: Request) -> tuple[str | None, str | None]:
    """Extract ip_address and user_agent from request for audit logging."""
    ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else None)
    )
    ua = request.headers.get("user-agent")
    return ip or None, ua or None


# ── Admin event logging helper ─────────────────────────────────────────────────

async def _log_admin_event(
    db:             AsyncSession,
    tenant_id:      uuid.UUID,
    actor_user_id:  uuid.UUID,
    action:         AdminEventAction,
    dept_id:        uuid.UUID | None = None,
    target_user_id: uuid.UUID | None = None,
    metadata:       dict | None      = None,
    ip_address:     str  | None      = None,
    user_agent:     str  | None      = None,
) -> None:
    """
    Inserts an admin_event row. Best-effort — never raises.
    Called after DB commit. Uses the same session (post-commit is safe).
    If logging fails, logs internally and continues.
    """
    try:
        from db.repositories.admin_event import AdminEventRepository
        repo = AdminEventRepository(db)
        await repo.insert(
            tenant_id      = tenant_id,
            actor_user_id  = actor_user_id,
            action         = action,
            dept_id        = dept_id,
            target_user_id = target_user_id,
            metadata       = metadata,
            ip_address     = ip_address,
            user_agent     = user_agent,
        )
        await db.commit()
    except Exception as e:
        logger.error(
            "admin_event logging failed action=%s actor=%s target=%s error=%s",
            action.value, actor_user_id, target_user_id, e,
        )


# ── Schemas ────────────────────────────────────────────────────────────────────

class UserCreateSchema(BaseModel):
    email:    EmailStr
    password: str
    role:     str
    dept_id:  str | None = None


class UserPatchSchema(BaseModel):
    role:      str  | None = None
    dept_id:   str  | None = None
    is_active: bool | None = None


class ResetPasswordSchema(BaseModel):
    new_password: str


# ── Validation helpers ─────────────────────────────────────────────────────────

def _validate_role_dept_consistency(role: str, dept_id) -> str | None:
    """
    Validates final state role + dept_id consistency.
    Returns error message string if invalid, None if valid.

    Rules (both directions enforced):
        role = ADMIN     → dept_id MUST be None
        role != ADMIN    → dept_id MUST NOT be None
    """
    if role == "ADMIN" and dept_id is not None:
        return "ADMIN users must not have a dept_id."
    if role != "ADMIN" and dept_id is None:
        return f"dept_id is required for role '{role}'."
    return None


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
    force_password_change = True always set.

    Auth: JWT + ADMIN role required.
    """
    from db.repositories.user import UserRepository
    from services.auth.password import (
        hash_password, normalize_email, validate_password_strength,
    )

    email = normalize_email(str(body.email))
    ip, ua = _get_client_info(request)

    try:
        validate_password_strength(body.password)
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": str(e)}},
        )

    # Validate role
    if body.role not in ("ADMIN", "DEVELOPER", "VIEWER"):
        return JSONResponse(
            status_code=400,
            content={"error": {
                "code":    "INVALID_REQUEST",
                "message": f"Invalid role '{body.role}'. Must be ADMIN, DEVELOPER, or VIEWER.",
            }},
        )

    # Validate final state: role + dept_id consistency
    error = _validate_role_dept_consistency(body.role, body.dept_id)
    if error:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": error}},
        )

    repo = UserRepository(db)

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

    # Log admin event (post-commit, best-effort)
    await _log_admin_event(
        db             = db,
        tenant_id      = uuid.UUID(str(principal.tenant_id)),
        actor_user_id  = uuid.UUID(str(principal.id).replace("user:", "")),
        action         = AdminEventAction.USER_CREATED,
        dept_id        = uuid.UUID(body.dept_id) if body.dept_id else None,
        target_user_id = user.id,
        metadata       = {
            "role":    body.role,
            "dept_id": body.dept_id,
        },
        ip_address     = ip,
        user_agent     = ua,
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
    Returns 404 if user belongs to a different tenant.

    Auth: JWT + ADMIN role required.
    """
    from db.repositories.user import UserRepository

    repo = UserRepository(db)
    user = await repo.get_by_id(uuid.UUID(user_id))

    if not user or str(user.tenant_id) != principal.tenant_id:
        raise NotFoundError("user", user_id)

    return JSONResponse(content=_format(user))


@router.patch("/{user_id}")
async def update_user(
    user_id:   str,
    body:      UserPatchSchema,
    request:   Request,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Partially updates a user's role, dept_id, or is_active.

    Validation performed on FINAL STATE (role + dept_id combined),
    not individual fields independently.

    Guards:
    - Admin cannot deactivate themselves
    - Cannot remove last ADMIN
    - dept_id must belong to same tenant

    Side effects:
    - role changed    → token_version++, admin_event: role_changed
    - dept changed    → token_version++, admin_event: dept_changed
    - deactivated     → token_version++, admin_event: user_deactivated
    - reactivated     → no token_version change, admin_event: user_reactivated

    Auth: JWT + ADMIN role required.
    """
    from db.repositories.user import UserRepository

    ip, ua = _get_client_info(request)
    actor_id = uuid.UUID(str(principal.id).replace("user:", ""))
    tenant_id = uuid.UUID(str(principal.tenant_id))

    repo = UserRepository(db)
    user = await repo.get_by_id(uuid.UUID(user_id))

    if not user or str(user.tenant_id) != principal.tenant_id:
        raise NotFoundError("user", user_id)

    data = body.model_dump(exclude_unset=True)

    if not data:
        return JSONResponse(content=_format(user))

    # Self-deactivation guard
    if data.get("is_active") is False and str(user.id) == str(actor_id):
        return JSONResponse(
            status_code=400,
            content={"error": {
                "code":    "INVALID_REQUEST",
                "message": "You cannot deactivate your own account.",
            }},
        )

    # Compute final state for validation
    final_role    = data.get("role",    user.role)
    final_dept_id = data.get("dept_id", str(user.dept_id) if user.dept_id else None)

    # Handle explicit dept_id = None in payload (allowed for ADMIN role change)
    if "dept_id" in data:
        final_dept_id = data["dept_id"]

    # Validate role (if changing)
    if "role" in data and data["role"] not in ("ADMIN", "DEVELOPER", "VIEWER"):
        return JSONResponse(
            status_code=400,
            content={"error": {
                "code":    "INVALID_REQUEST",
                "message": f"Invalid role '{data['role']}'. Must be ADMIN, DEVELOPER, or VIEWER.",
            }},
        )

    # Final state validation: role + dept_id consistency
    error = _validate_role_dept_consistency(final_role, final_dept_id)
    if error:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": error}},
        )

    # Last-admin protection
    new_role      = data.get("role")
    new_is_active = data.get("is_active")

    is_demoting_admin     = (user.role == "ADMIN" and new_role is not None and new_role != "ADMIN")
    is_deactivating_admin = (user.role == "ADMIN" and new_is_active is False)

    if is_demoting_admin or is_deactivating_admin:
        active_admins = await repo.count_active_admins(tenant_id)
        if active_admins <= 1:
            return JSONResponse(
                status_code=400,
                content={"error": {
                    "code":    "INVALID_REQUEST",
                    "message": "Cannot demote or deactivate the last active admin. "
                               "Create another admin first.",
                }},
            )

    # Convert dept_id to UUID if provided and not None
    if "dept_id" in data and data["dept_id"] is not None:
        data["dept_id"] = uuid.UUID(data["dept_id"])

    # Capture old values for audit metadata before update
    old_role    = user.role
    old_dept_id = str(user.dept_id) if user.dept_id else None

    try:
        updated = await repo.update(uuid.UUID(user_id), data)
        await db.commit()
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": str(e)}},
        )

    # Session invalidation
    invalidate_session = (
        new_role is not None or
        "dept_id" in data or
        new_is_active is False
    )
    if invalidate_session:
        await auth_service.logout_all_sessions(uuid.UUID(user_id), db)

    # Admin event logging — one event per change type, post-commit, best-effort
    target_uuid = uuid.UUID(user_id)
    post_dept_id = updated.dept_id  # post-update value for dept_id rows

    if new_role is not None and new_role != old_role:
        await _log_admin_event(
            db             = db,
            tenant_id      = tenant_id,
            actor_user_id  = actor_id,
            action         = AdminEventAction.ROLE_CHANGED,
            dept_id        = post_dept_id,
            target_user_id = target_uuid,
            metadata       = {"old_role": old_role, "new_role": new_role},
            ip_address     = ip,
            user_agent     = ua,
        )

    if "dept_id" in data:
        new_dept_str = str(data["dept_id"]) if data["dept_id"] else None
        if new_dept_str != old_dept_id:
            await _log_admin_event(
                db             = db,
                tenant_id      = tenant_id,
                actor_user_id  = actor_id,
                action         = AdminEventAction.DEPT_CHANGED,
                dept_id        = post_dept_id,   # new dept_id (post-update)
                target_user_id = target_uuid,
                metadata       = {
                    "old_dept_id": old_dept_id,
                    "new_dept_id": new_dept_str,
                },
                ip_address     = ip,
                user_agent     = ua,
            )

    if new_is_active is False:
        await _log_admin_event(
            db             = db,
            tenant_id      = tenant_id,
            actor_user_id  = actor_id,
            action         = AdminEventAction.USER_DEACTIVATED,
            dept_id        = post_dept_id,
            target_user_id = target_uuid,
            ip_address     = ip,
            user_agent     = ua,
        )

    if new_is_active is True:
        await _log_admin_event(
            db             = db,
            tenant_id      = tenant_id,
            actor_user_id  = actor_id,
            action         = AdminEventAction.USER_REACTIVATED,
            dept_id        = post_dept_id,
            target_user_id = target_uuid,
            ip_address     = ip,
            user_agent     = ua,
        )

    return JSONResponse(content=_format(updated))


@router.post("/{user_id}/reset-password")
async def reset_password(
    user_id:   str,
    body:      ResetPasswordSchema,
    request:   Request,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Admin resets a user's password.
    Sets force_password_change = True.
    Invalidates all active sessions.

    Auth: JWT + ADMIN role required.
    """
    from db.repositories.user import UserRepository
    from services.auth.password import hash_password, validate_password_strength

    ip, ua = _get_client_info(request)
    actor_id  = uuid.UUID(str(principal.id).replace("user:", ""))
    tenant_id = uuid.UUID(str(principal.tenant_id))

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

    # Log admin event (post-commit, best-effort)
    await _log_admin_event(
        db             = db,
        tenant_id      = tenant_id,
        actor_user_id  = actor_id,
        action         = AdminEventAction.PASSWORD_RESET,
        dept_id        = user.dept_id,
        target_user_id = uuid.UUID(user_id),
        ip_address     = ip,
        user_agent     = ua,
    )

    return JSONResponse(content={
        "message": "Password reset. User must change password on next login.",
        "user_id": user_id,
    })
