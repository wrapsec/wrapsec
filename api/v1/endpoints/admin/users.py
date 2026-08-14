# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import endpoint_rate_limit, require_admin
from api.v1.dependencies.db import get_db
from api.v1.middleware.auth import get_client_ip
from db.repositories.admin_event import AdminEventRepository
from db.repositories.membership import MembershipRepository
from db.repositories.user import UserRepository
from domain.entities.principal import Principal
from domain.enums import AdminEventAction
from errors.catalog import ErrorCode
from errors.exceptions import NotFoundError
from errors.response import error_response
from services.auth.password import (
    hash_password,
    normalize_email,
    validate_password_strength,
)
from services.auth.service import AuthService
from services.time import to_iso_z

router = APIRouter()
logger = logging.getLogger("wrapsec.admin.users")


# ── Formatters ─────────────────────────────────────────────────────────────────

def _format(user, membership) -> dict:
    """Identity fields from the user; authz (role/dept/tenant) from the membership."""
    return {
        "id":                    str(user.id),
        "email":                 user.email,
        "role":                  membership.role,
        "dept_id":               str(membership.dept_id) if membership.dept_id else None,
        "tenant_id":             str(membership.tenant_id),
        "is_active":             user.is_active,
        "force_password_change": user.force_password_change,
        "created_at":            to_iso_z(user.created_at),
        "last_login_at":         to_iso_z(user.last_login_at) if user.last_login_at else None,
    }


def _get_client_info(request: Request) -> tuple[str | None, str | None]:
    """Extract ip_address and user_agent from request for audit logging."""
    ip = get_client_ip(request)
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
    Inserts an admin_event row. Best-effort - never raises.
    Called after DB commit. Uses the same session (post-commit is safe).
    If logging fails, logs internally and continues.
    """
    try:
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

    Rules (mirror ck_users_dept_required_v2 in db/models.py):
        role = ADMIN                 -> dept_id MUST be None
        role = AUDITOR               -> dept_id may be None (tenant-wide)
                                        or set (department-scoped)
        role IN (DEVELOPER, VIEWER)  -> dept_id MUST NOT be None
    """
    if role == "ADMIN" and dept_id is not None:
        return "ADMIN users must not have a dept_id."
    if role == "AUDITOR":
        return None
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
    _rl:       None         = Depends(endpoint_rate_limit("admin_write_rate_limit")),
) -> JSONResponse:
    """
    Creates a new dashboard user.
    force_password_change = True always set.

    Auth: JWT + ADMIN role required.
    """
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
    if body.role not in ("ADMIN", "DEVELOPER", "VIEWER", "AUDITOR"):
        return JSONResponse(
            status_code=400,
            content={"error": {
                "code":    "INVALID_REQUEST",
                "message": f"Invalid role '{body.role}'. Must be ADMIN, DEVELOPER, VIEWER, or AUDITOR.",
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

    if body.dept_id:
        try:
            _dept_uuid = uuid.UUID(body.dept_id)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"error": {"code": "INVALID_REQUEST", "message": "dept_id must be a valid UUID."}},
            )
        # M4: the department must belong to the caller's tenant. The FK guarantees
        # the dept exists, not that it is yours; mirror keys.py app/dept resolution.
        from db.repositories.department import DepartmentRepository
        _dept = await DepartmentRepository(db).get_by_id(_dept_uuid)
        if not _dept or str(_dept.tenant_id) != str(principal.tenant_id):
            raise NotFoundError("department", body.dept_id)

    try:
        _tenant_uuid = uuid.UUID(str(principal.tenant_id))
        _dept_uuid   = uuid.UUID(body.dept_id) if body.dept_id else None
        user = await repo.create({
            "email":                 email,
            "password_hash":         hash_password(body.password),
            "force_password_change": True,
        })
        await repo.flush()  # assign user.id before the membership FK references it
        # The membership is the authz record: role/dept in this tenant.
        membership = await MembershipRepository(db).upsert_for_user(
            user_id=user.id, tenant_id=_tenant_uuid, role=body.role, dept_id=_dept_uuid,
        )
        await db.commit()
    except ValueError as e:
        logger.warning("user create rejected: %s", e)
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": "Invalid request parameters."}},
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

    return JSONResponse(status_code=201, content=_format(user, membership))


@router.get("")
async def list_users(
    request:   Request,
    role:      str  | None = None,
    is_active: bool | None = None,
    limit:     int  = Query(50, ge=1, le=200),
    offset:    int  = Query(0, ge=0),
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Lists all users for the tenant.
    Scoped to principal.tenant_id - never cross-tenant.

    Auth: JWT + ADMIN role required.
    """
    rows, total = await MembershipRepository(db).list_in_tenant(
        tenant_id = uuid.UUID(str(principal.tenant_id)),
        role      = role,
        is_active = is_active,
        limit     = limit,
        offset    = offset,
    )

    return JSONResponse(content={
        "total": total,
        "users": [_format(u, m) for (m, u) in rows],
    })


@router.get("/{user_id}")
async def get_user(
    user_id:   uuid.UUID,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Returns a single user by ID.
    Returns 404 if user belongs to a different tenant.

    Auth: JWT + ADMIN role required.
    """
    user       = await UserRepository(db).get_by_id(user_id)
    membership = (
        await MembershipRepository(db).get_by_user_and_tenant(
            user_id, uuid.UUID(str(principal.tenant_id))
        )
        if user else None
    )
    # A user "belongs to" the tenant iff they hold a membership in it.
    if not user or membership is None:
        raise NotFoundError("user", str(user_id))

    return JSONResponse(content=_format(user, membership))


@router.patch("/{user_id}")
async def update_user(
    user_id:   uuid.UUID,
    body:      UserPatchSchema,
    request:   Request,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
    _rl:       None         = Depends(endpoint_rate_limit("admin_write_rate_limit")),
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
    - role changed    -> token_version++, admin_event: role_changed
    - dept changed    -> token_version++, admin_event: dept_changed
    - deactivated     -> token_version++, admin_event: user_deactivated
    - reactivated     -> no token_version change, admin_event: user_reactivated

    Auth: JWT + ADMIN role required.
    """
    ip, ua = _get_client_info(request)
    actor_id  = uuid.UUID(str(principal.id).replace("user:", ""))
    tenant_id = uuid.UUID(str(principal.tenant_id))

    repo     = UserRepository(db)
    mem_repo = MembershipRepository(db)
    user       = await repo.get_by_id(user_id)
    membership = await mem_repo.get_by_user_and_tenant(user_id, tenant_id) if user else None

    if not user or membership is None:
        raise NotFoundError("user", str(user_id))

    data = body.model_dump(exclude_unset=True)

    if not data:
        return JSONResponse(content=_format(user, membership))

    # Self-deactivation guard
    if data.get("is_active") is False and str(user.id) == str(actor_id):
        logger.info(
            "self-deactivation blocked actor=%s tenant=%s", actor_id, tenant_id,
        )
        return error_response(
            ErrorCode.CANNOT_DEACTIVATE_SELF,
            trace_id=getattr(request.state, "trace_id", "") or "",
        )

    # Compute final state for validation (authz comes from the membership)
    final_role    = data.get("role",    membership.role)
    final_dept_id = data.get("dept_id", str(membership.dept_id) if membership.dept_id else None)

    # Handle explicit dept_id = None in payload (allowed for ADMIN role change)
    if "dept_id" in data:
        final_dept_id = data["dept_id"]

    # Validate role (if changing)
    if "role" in data and data["role"] not in ("ADMIN", "DEVELOPER", "VIEWER", "AUDITOR"):
        return JSONResponse(
            status_code=400,
            content={"error": {
                "code":    "INVALID_REQUEST",
                "message": f"Invalid role '{data['role']}'. Must be ADMIN, DEVELOPER, VIEWER, or AUDITOR.",
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

    is_demoting_admin     = (membership.role == "ADMIN" and new_role is not None and new_role != "ADMIN")
    is_deactivating_admin = (membership.role == "ADMIN" and new_is_active is False)

    if is_demoting_admin or is_deactivating_admin:
        active_admins = await mem_repo.count_active_admins_for_update(tenant_id, user_id)
        if active_admins <= 1:
            logger.info(
                "last-admin guard blocked actor=%s target=%s tenant=%s",
                actor_id, user_id, tenant_id,
            )
            return error_response(
                ErrorCode.LAST_ADMIN,
                trace_id=getattr(request.state, "trace_id", "") or "",
            )

    # Convert dept_id to UUID if provided and not None
    if "dept_id" in data and data["dept_id"] is not None:
        try:
            data["dept_id"] = uuid.UUID(data["dept_id"])
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"error": {"code": "INVALID_REQUEST", "message": "dept_id must be a valid UUID."}},
            )
        # M4: the department must belong to the caller's tenant (mirror keys.py).
        from db.repositories.department import DepartmentRepository
        _dept = await DepartmentRepository(db).get_by_id(data["dept_id"])
        if not _dept or str(_dept.tenant_id) != str(principal.tenant_id):
            raise NotFoundError("department", str(data["dept_id"]))

    # Capture old values for audit metadata before update (from the membership)
    old_role    = membership.role
    old_dept_id = str(membership.dept_id) if membership.dept_id else None

    try:
        # Only account state (is_active) lands on the user row; role/dept are
        # authz and live on the membership.
        updated = await repo.update(user_id, {k: v for k, v in data.items() if k == "is_active"})
        if updated is None:
            raise NotFoundError("user", str(user_id))
        # Authz writes land on the membership. Only when role/dept actually change
        # (is_active-only updates leave authz untouched).
        if "role" in data or "dept_id" in data:
            await repo.flush()
            _final_dept_uuid = uuid.UUID(final_dept_id) if final_dept_id else None
            membership = await mem_repo.upsert_for_user(
                user_id=user_id, tenant_id=tenant_id,
                role=final_role, dept_id=_final_dept_uuid,
            )
        # Do NOT commit yet - session invalidation must be atomic with the update.
    except ValueError as e:
        logger.warning("user update rejected: %s", e)
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": "Invalid request parameters."}},
        )

    # Enqueue account/role notifications on THIS session so they commit
    # atomically with the update below (session invalidation / the else-branch
    # issues the commit). Enqueue is a local INSERT -- SMTP is not touched here.
    from services.email.notifications import (
        notify_account_deactivated,
        notify_account_reactivated,
        notify_role_changed,
    )
    _trace = getattr(request.state, "trace_id", None)
    if new_is_active is False:
        await notify_account_deactivated(db, updated, trace_id=_trace)
    elif new_is_active is True:
        await notify_account_reactivated(db, updated, trace_id=_trace)
    if new_role is not None and new_role != old_role:
        await notify_role_changed(db, updated, new_role=new_role, trace_id=_trace)

    # Session invalidation - commits the user update + invalidation atomically.
    invalidate_session = (
        new_role is not None or
        "dept_id" in data or
        new_is_active is False
    )
    if invalidate_session:
        await AuthService().logout_all_sessions(user_id, db)
        # logout_all_sessions() issues db.commit() - user update is now persisted.
    else:
        await db.commit()

    # Admin event logging - one event per change type, post-commit, best-effort
    target_uuid = user_id
    post_dept_id = membership.dept_id  # post-update dept from the membership

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

    return JSONResponse(content=_format(updated, membership))


@router.post("/{user_id}/reset-password")
async def reset_password(
    user_id:   uuid.UUID,
    body:      ResetPasswordSchema,
    request:   Request,
    principal: Principal    = Depends(require_admin()),
    db:        AsyncSession = Depends(get_db),
    _rl:       None         = Depends(endpoint_rate_limit("admin_write_rate_limit")),
) -> JSONResponse:
    """
    Admin resets a user's password.
    Sets force_password_change = True.
    Invalidates all active sessions.

    Auth: JWT + ADMIN role required.
    """
    ip, ua = _get_client_info(request)
    actor_id  = uuid.UUID(str(principal.id).replace("user:", ""))
    tenant_id = uuid.UUID(str(principal.tenant_id))

    repo       = UserRepository(db)
    user       = await repo.get_by_id(user_id)
    membership = await MembershipRepository(db).get_by_user_and_tenant(user_id, tenant_id) if user else None

    if not user or membership is None:
        raise NotFoundError("user", str(user_id))

    try:
        validate_password_strength(body.new_password)
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "INVALID_REQUEST", "message": str(e)}},
        )

    await repo.update(user_id, {
        "password_hash":         hash_password(body.new_password),
        "force_password_change": True,
    })
    # Enqueue the admin-reset notification on this session so it commits
    # atomically with the password change (enqueue is a local INSERT; SMTP is
    # not touched here). Recipient is the target user's stored email.
    from services.email.notifications import notify_admin_password_reset
    await notify_admin_password_reset(
        db, user, trace_id=getattr(request.state, "trace_id", None)
    )
    await db.commit()

    await AuthService().logout_all_sessions(user_id, db)

    # Log admin event (post-commit, best-effort)
    await _log_admin_event(
        db             = db,
        tenant_id      = tenant_id,
        actor_user_id  = actor_id,
        action         = AdminEventAction.PASSWORD_RESET,
        dept_id        = membership.dept_id,
        target_user_id = user_id,
        ip_address     = ip,
        user_agent     = ua,
    )

    return JSONResponse(content={
        "message": "Password reset. User must change password on next login.",
        "user_id": str(user_id),
    })
