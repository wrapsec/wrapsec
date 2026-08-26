# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
import logging
import secrets
import uuid
from datetime import timedelta
from enum import Enum
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal, require_admin
from api.v1.dependencies.db import get_db
from api.v1.middleware.auth import get_client_ip
from api.v1.schemas.response import (
    ApiKeyCreated,
    ApiKeyListResponse,
    ErrorEnvelope,
)
from db.models import AuditLogModel, AuthEventModel
from db.repositories.admin_event import AdminEventRepository
from db.repositories.api_key import ApiKeyRepository
from db.repositories.application import ApplicationRepository
from db.repositories.department import DepartmentRepository
from domain.entities.principal import Principal
from domain.enums import AdminEventAction, AuthEventAction
from errors.exceptions import NotFoundError
from services.time import parse_utc_iso, to_iso_z, utc_now

logger = logging.getLogger("wrapsec.keys")

router = APIRouter()

# Reachable failures on the two PUBLIC key routes. Creation is JWT + ADMIN, so a
# key presented here is refused before the handler runs. 422 is declared because
# the runtime handler returns the catalog envelope -- an invalid `key_type`, a
# malformed `expires_at`, or an admin with no department and no explicit scope.
_CREATE_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Missing or invalid credentials."},
    403: {"model": ErrorEnvelope, "description": "Not an ADMIN, or the principal has no tenant scope."},
    404: {"model": ErrorEnvelope, "description": "The named application or department does not exist in this tenant."},
    422: {"model": ErrorEnvelope, "description": "Request body failed validation, or no department could be resolved for the key."},
}

_LIST_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Missing or invalid credentials."},
}


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_api_key(key_type: str = "live") -> str:
    prefix = "wsk_trial_" if key_type == "trial" else "wsk_live_"
    return prefix + secrets.token_urlsafe(32)


def generate_key_id() -> str:
    return "key_" + secrets.token_hex(6)


class KeyType(str, Enum):
    LIVE  = "live"
    TRIAL = "trial"


class CreateKeySchema(BaseModel):
    name:       str = Field(min_length=1, max_length=100)
    dept_id:    str | None = None  # dept-scoped key (no app required)
    app_id:     str | None = None  # app-scoped key (dept+tenant derived from app)
    key_type:   KeyType = KeyType.LIVE
    expires_at: str | None = None
    # Source networks this credential may be used from. Omitted or empty means
    # unrestricted, so the control stays opt-in.
    ip_allowlist: list[str] | None = None

    @field_validator("dept_id", "app_id")
    @classmethod
    def _valid_uuid(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            uuid.UUID(v)
        except ValueError:
            raise ValueError("must be a valid UUID") from None
        return v

    @field_validator("expires_at")
    @classmethod
    def _valid_expires_at(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from services.time import parse_utc_iso
        try:
            parse_utc_iso(v)
        except Exception:
            raise ValueError("expires_at must be an ISO-8601 datetime") from None
        return v

    @field_validator("ip_allowlist")
    @classmethod
    def _valid_allowlist(cls, v: list[str] | None) -> list[str] | None:
        """
        Store what was understood, not what was typed.

        Entries are canonicalised here so a malformed block is refused while the
        operator is looking at it. Accepting it would leave enforcement silently
        skipping that entry, which reads as "this network is not permitted"
        rather than as the configuration error it is.
        """
        if v is None:
            return None
        from security.ip_allowlist import normalize_entries
        return normalize_entries(v)


async def _record_allowlist_change(
    db,
    request,
    principal,
    key_id:    str,
    dept_id,
    previous:  list[str] | None,
    current:   list[str] | None,
) -> None:
    """
    Record a change to where a credential may be used.

    Whoever can set an allowlist can also remove it, so the change itself is the
    security event: without this, widening a restricted credential to everywhere
    would leave no trace. Only the shape of the change and the networks involved
    are recorded -- never the key secret.

    Best-effort, like the other administrative events: the change is already
    committed and must not be undone by an audit write failing.
    """
    before = previous or []
    after  = current  or []
    if before == after:
        return

    if not before:
        change = "added"
    elif not after:
        change = "removed"
    else:
        change = "changed"

    try:
        event_repo = AdminEventRepository(db)
        await event_repo.insert(
            tenant_id     = uuid.UUID(request.state.tenant_id),
            actor_user_id = uuid.UUID(str(principal.id).replace("user:", "")),
            action        = AdminEventAction.KEY_ALLOWLIST_CHANGED,
            dept_id       = dept_id,
            metadata      = {
                "key_id":          key_id,
                "change":          change,
                "previous":        before,
                "current":         after,
                "previous_count":  len(before),
                "current_count":   len(after),
            },
            ip_address    = get_client_ip(request),
            user_agent    = request.headers.get("user-agent"),
        )
        await db.commit()
    except Exception as e:
        logger.error(
            "admin_event write failed action=key_allowlist_changed key_id=%s error=%s",
            key_id, e,
        )


@router.post(
    "",
    response_model               = ApiKeyCreated,
    # 201 stays the contract: it was carried by the constructed JSONResponse and
    # now sits on the route, so the body can be returned as a value and pass
    # through the model.
    status_code                  = 201,
    response_model_exclude_unset = True,
    responses                    = _CREATE_ERRORS,
)
async def create_key(
    body:      CreateKeySchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Creates an API key. Scope resolution follows a three-tier chain:
      app_id provided  -> derive dept + tenant from the app record
      dept_id provided -> derive tenant from the dept record
      neither          -> use the authenticated principal's tenant/dept

    The raw key value is returned once and cannot be retrieved again.
    Auth: JWT + ADMIN role required.
    """
    # Tenant must be known before any key is created - keys without a tenant
    # bypass tenant isolation checks in every downstream auth path.
    if not request.state.tenant_id:
        from errors.exceptions import WrapSecError
        raise WrapSecError(
            code        = "FORBIDDEN",
            message     = "Cannot create API key: authenticated principal has no tenant scope",
            status_code = 403,
        )

    # key_type is validated by the KeyType enum at parse time (invalid values
    # produce a structured 422 INVALID_ENUM), so no manual check is needed here.
    api_key = generate_api_key(body.key_type)
    key_id  = generate_key_id()

    # Resolve app -> dept -> tenant chain
    app_id    = None
    dept_id   = None
    tenant_id = None

    if body.app_id:
        # App-scoped key: derive dept + tenant from app
        app_repo = ApplicationRepository(db)
        app      = await app_repo.get_by_id(uuid.UUID(body.app_id))
        if not app or str(app.tenant_id) != request.state.tenant_id:
            raise NotFoundError(resource="application", identifier=body.app_id)
        app_id    = app.id
        dept_id   = app.dept_id
        tenant_id = app.tenant_id
    elif body.dept_id:
        # Dept-scoped key: derive tenant from dept
        dept_repo = DepartmentRepository(db)
        dept      = await dept_repo.get_by_id(uuid.UUID(body.dept_id))
        if not dept or str(dept.tenant_id) != request.state.tenant_id:
            raise NotFoundError(resource="department", identifier=body.dept_id)
        dept_id   = dept.id
        tenant_id = dept.tenant_id
    else:
        # No scope specified - use authenticated tenant (guaranteed non-None by guard above)
        tenant_id = uuid.UUID(request.state.tenant_id)
        if request.state.dept_id:
            dept_id = uuid.UUID(request.state.dept_id)

    # Reject non-admin keys that resolve to no department. Without dept_id, the
    # scope dependency (api/v1/dependencies/scope.py) falls through to tenant-
    # scoped audit reads, letting the key see other departments' audit records
    # within its tenant. The DB CheckConstraint enforces this too, but rejecting
    # here returns a clear 422 instead of a 500 from constraint violation.
    if dept_id is None:
        from errors.catalog import VALIDATION_CATALOG, ValidationCode
        from errors.exceptions import WrapSecError

        # `dept_id` is a real field on this request, so the condition belongs in
        # `invalid_params` rather than in an English sentence the caller has to
        # parse. Only `dept_id` is reported, not `app_id`: neither is required on
        # its own -- supplying the app is one way to RESOLVE a department -- and
        # marking both REQUIRED would tell the caller to send two fields when
        # either one suffices.
        #
        # The full guidance stays in the log line, where the detail is useful to
        # whoever is debugging the caller's integration.
        raise WrapSecError(
            code           = "VALIDATION_ERROR",
            status_code    = 422,
            debug_message  = (
                "dept_id is required to create an API key. Admins without a "
                "department must specify app_id (dept derived from app) or "
                "dept_id (dept-scoped key) explicitly."
            ),
            invalid_params = [{
                "field":  "dept_id",
                "code":   ValidationCode.REQUIRED.value,
                "key":    VALIDATION_CATALOG[ValidationCode.REQUIRED],
                "params": {},
            }],
        )

    # Persist expires_at (validated to ISO-8601 by the schema). Omitting it here
    # was silently dropping the expiry: the key was stored with NULL expires_at
    # and never expired, while the response still advertised the requested expiry.
    expires_at = parse_utc_iso(body.expires_at) if body.expires_at else None

    repo   = ApiKeyRepository(db)
    record = await repo.create({
        "key_id":     key_id,
        "name":       body.name,
        "key_hash":   _hash_key(api_key),
        "key_type":   body.key_type.value,
        "is_admin":   False,
        "revoked":    False,
        "app_id":     app_id,
        "dept_id":    dept_id,
        "tenant_id":  tenant_id,
        "expires_at": expires_at,
        "ip_allowlist": body.ip_allowlist or None,
    })
    await db.commit()

    if body.ip_allowlist:
        await _record_allowlist_change(
            db, request, principal, key_id, dept_id,
            previous=None, current=body.ip_allowlist,
        )

    # A value, not a JSONResponse: a Response object bypasses the response model,
    # and this is the one body in the API that carries a credential -- the last
    # place to leave unfiltered.
    return {
        "key_id":     key_id,
        "name":       body.name,
        "api_key":    api_key,
        "key_type":   body.key_type.value,
        "app_id":     str(app_id)    if app_id    else None,
        "dept_id":    str(dept_id)   if dept_id   else None,
        "tenant_id":  str(tenant_id) if tenant_id else None,
        "created_at": to_iso_z(record.created_at),
        "expires_at": to_iso_z(record.expires_at) if record.expires_at else None,
    }


@router.get(
    "",
    response_model               = ApiKeyListResponse,
    response_model_exclude_unset = True,
    responses                    = _LIST_ERRORS,
)
async def list_keys(
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),
):
    """
    Lists all active, non-expired keys for the authenticated principal's tenant.
    Each key is enriched with department name and application name where available.
    Keys past their grace-period expiry are excluded from the response.
    """
    tenant_id = uuid.UUID(request.state.tenant_id) if request.state.tenant_id else None
    repo = ApiKeyRepository(db)
    keys = await repo.list_active(tenant_id=tenant_id)
    # Filter out keys whose grace period has expired
    now  = utc_now()
    keys = [k for k in keys if k.expires_at is None or k.expires_at > now]

    # C1: a non-admin principal sees only its own department's keys, not every
    # key across the tenant. Admins (no dept scope) see all tenant keys.
    if not request.state.is_admin and request.state.dept_id:
        own_dept = str(request.state.dept_id)
        keys = [k for k in keys if k.dept_id and str(k.dept_id) == own_dept]

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

    # A value, not a JSONResponse. The model here declares no credential field at
    # all, so the filter cannot pass one through even if a writer added it.
    return {
        "keys": [
            {
                "key_id":       k.key_id,
                "name":         k.name,
                "app_id":       str(k.app_id)  if k.app_id  else None,
                "dept_id":      str(k.dept_id) if k.dept_id else None,
                "dept_name":    dept_names.get(str(k.dept_id)) if k.dept_id else None,
                "app_name":     app_names.get(str(k.app_id))   if k.app_id  else None,
                "key_type":     getattr(k, "key_type", "live") or "live",
                "created_at":   to_iso_z(k.created_at),
                "expires_at":   to_iso_z(k.expires_at) if k.expires_at else None,
                "last_used_at": to_iso_z(k.last_used_at) if k.last_used_at else None,
            }
            for k in keys
        ]
    }

# Key lifecycle beyond list and create is dashboard surface today: the
# published integrator contract is GET and POST /v1/keys. These five stay
# served and authorized unchanged; revisit if an SDK grows key management.
@router.get("/{key_id}", include_in_schema=False)
async def get_key(
    key_id:    str,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),
):
    """Returns full metadata for a single key by key_id. 404 if not found."""
    repo   = ApiKeyRepository(db)
    record = await repo.get_active_by_key_id(key_id)
    if not record or str(record.tenant_id) != request.state.tenant_id:
        raise NotFoundError("key", key_id)
    # C1: non-admin principals are confined to their own department's keys.
    if (not request.state.is_admin and request.state.dept_id
            and str(record.dept_id) != str(request.state.dept_id)):
        raise NotFoundError("key", key_id)

    body = {
        "key_id":       record.key_id,
        "name":         record.name,
        "app_id":       str(record.app_id)    if record.app_id    else None,
        "dept_id":      str(record.dept_id)   if record.dept_id   else None,
        "tenant_id":    str(record.tenant_id) if record.tenant_id else None,
        "key_type":     getattr(record, "key_type", "live") or "live",
        "is_admin":     record.is_admin,
        "revoked":      record.revoked,
        "created_at":   to_iso_z(record.created_at),
        "expires_at":   to_iso_z(record.expires_at) if record.expires_at else None,
        "last_used_at": to_iso_z(record.last_used_at) if record.last_used_at else None,
    }

    # The networks a credential is confined to describe where an organisation
    # operates from, so they are shown only to whoever can change them. This
    # route is readable by a department member, not just an administrator, and
    # the key listing is broader still.
    if request.state.is_admin:
        body["ip_allowlist"] = list(record.ip_allowlist or [])

    return JSONResponse(content=body)

class UpdateKeySchema(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    # Omitted leaves the allowlist untouched; an empty list clears it, returning
    # the credential to unrestricted.
    ip_allowlist: list[str] | None = None

    @field_validator("ip_allowlist")
    @classmethod
    def _valid_allowlist(cls, v: list[str] | None) -> list[str] | None:
        """
        Store what was understood, not what was typed.

        Entries are canonicalised here so a malformed block is refused while the
        operator is looking at it. Accepting it would leave enforcement silently
        skipping that entry, which reads as "this network is not permitted"
        rather than as the configuration error it is.
        """
        if v is None:
            return None
        from security.ip_allowlist import normalize_entries
        return normalize_entries(v)

@router.put("/{key_id}", include_in_schema=False)
async def update_key(
    key_id:    str,
    body:      UpdateKeySchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """Renames an API key. Does not rotate the key secret. Auth: JWT + ADMIN required."""
    repo   = ApiKeyRepository(db)
    record = await repo.get_active_by_key_id(key_id)
    if not record or str(record.tenant_id) != request.state.tenant_id:
        raise NotFoundError("key", key_id)

    previous_allowlist = list(record.ip_allowlist or [])

    record.name = body.name
    # Omitted leaves the restriction as it was; an empty list clears it.
    if body.ip_allowlist is not None:
        record.ip_allowlist = body.ip_allowlist or None
    await db.commit()

    if body.ip_allowlist is not None:
        await _record_allowlist_change(
            db, request, principal, record.key_id, record.dept_id,
            previous=previous_allowlist, current=body.ip_allowlist,
        )

    return JSONResponse(content={
        "key_id":       record.key_id,
        "name":         record.name,
        "ip_allowlist": list(record.ip_allowlist or []),
        "updated_at":   to_iso_z(utc_now()),
    })

@router.delete("/{key_id}", include_in_schema=False)
async def delete_key(
    key_id:    str,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Revokes an API key immediately. If the key is still in a rotation grace period,
    it is revoked early and a warning is included in the response.
    Auth: JWT + ADMIN role required.
    """
    repo   = ApiKeyRepository(db)
    record = await repo.get_active_by_key_id(key_id)
    if not record or str(record.tenant_id) != request.state.tenant_id:
        raise NotFoundError("key", key_id)

    was_in_grace = record.expires_at is not None and not record.revoked

    await repo.revoke(key_id)
    await db.commit()

    return JSONResponse(content={
        "key_id":          key_id,
        "revoked":         True,
        "revoked_at":      to_iso_z(utc_now()),
        "was_in_grace":    was_in_grace,
        "warning":         (
            "Key was in grace period and has been immediately revoked. "
            "Integrations using the old key will stop working now."
        ) if was_in_grace else None,
    })

class RotateKeySchema(BaseModel):
    grace_period_minutes: int = Field(60, ge=0, le=10080)  # 0 = immediate, max 7 days


@router.get("/{key_id}/addresses", include_in_schema=False)
async def get_key_addresses(
    key_id:    str,
    request:   Request,
    days:      int = 30,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Where this credential has been used from, and where it has been refused.

    Building a source-network list from memory is how an operator locks out
    production. These are the two lists that make it an informed decision:
    addresses the credential actually authenticated from, and addresses it was
    turned away from -- the second being what an operator needs when production
    moves to a new egress address and the key starts failing.

    Administrator only, matching the write path. The networks a credential is
    confined to, and the addresses it is used from, describe where an
    organisation operates; they are shown only to whoever can change them.

    Auth: JWT + ADMIN required. 404 if the key belongs to another tenant.
    """
    repo   = ApiKeyRepository(db)
    record = await repo.get_active_by_key_id(key_id)
    if not record or str(record.tenant_id) != request.state.tenant_id:
        raise NotFoundError("key", key_id)

    window = max(1, min(days, 365))
    since  = utc_now() - timedelta(days=window)

    # The two tables record the credential differently. Request state carries a
    # prefixed form to distinguish credential kinds, and the request trail stores
    # it verbatim, while the credential log stores the bare id so it joins the
    # key table. Querying either with the other's format silently returns
    # nothing, which reads as "never used" rather than as a bug.
    #
    # Both reads carry the tenant as well. The key was already resolved and
    # confirmed to belong to this tenant, and key ids are unique, so the filter
    # is redundant today -- it is here so that a future id collision, or a
    # lookup that stops checking ownership, cannot turn this into a window onto
    # another organisation's infrastructure.
    used = (await db.execute(
        select(
            AuditLogModel.ip_address,
            func.count().label("hits"),
            func.max(AuditLogModel.created_at).label("last_seen"),
        )
        .where(
            AuditLogModel.tenant_id  == request.state.tenant_id,
            AuditLogModel.key_id     == f"key:{key_id}",
            AuditLogModel.ip_address.is_not(None),
            AuditLogModel.created_at >= since,
        )
        .group_by(AuditLogModel.ip_address)
        .order_by(func.max(AuditLogModel.created_at).desc())
        .limit(20)
    )).all()

    denied = (await db.execute(
        select(
            AuthEventModel.ip_address,
            func.count().label("hits"),
            func.max(AuthEventModel.created_at).label("last_seen"),
        )
        .where(
            AuthEventModel.tenant_id  == uuid.UUID(request.state.tenant_id),
            AuthEventModel.key_id     == key_id,
            AuthEventModel.action     == AuthEventAction.API_KEY_IP_DENIED.value,
            AuthEventModel.ip_address.is_not(None),
            AuthEventModel.created_at >= since,
        )
        .group_by(AuthEventModel.ip_address)
        .order_by(func.max(AuthEventModel.created_at).desc())
        .limit(20)
    )).all()

    def _rows(rows):
        return [
            {
                "ip_address": row.ip_address,
                "count":      int(row.hits),
                "last_seen":  to_iso_z(row.last_seen),
            }
            for row in rows
        ]

    return JSONResponse(content={
        "key_id":      key_id,
        "window_days": window,
        "observed":    _rows(used),
        "denied":      _rows(denied),
    })


@router.post("/{key_id}/rotate", include_in_schema=False)
async def rotate_key(
    key_id:    str,
    body:      RotateKeySchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Rotate an API key - generates a new secret while preserving all metadata.
    Old key remains valid for grace_period_minutes to allow graceful migration.
    After grace period, old key is automatically revoked.

    Returns the new key secret - shown once, store securely.
    """
    repo   = ApiKeyRepository(db)
    # get_active_by_key_id only returns non-revoked keys, so a revoked key resolves to
    # None and 404s here - no separate revoked-key branch is reachable.
    record = await repo.get_active_by_key_id(key_id)
    if not record or str(record.tenant_id) != request.state.tenant_id:
        raise NotFoundError("key", key_id)

    if record.expires_at is not None:
        now = utc_now()
        if record.expires_at > now:
            # Still in grace period
            return JSONResponse(
                content={"error": {"code": "KEY_IN_GRACE_PERIOD", "message": (
                    f"This key has already been rotated and is in its grace period "
                    f"(expires at {to_iso_z(record.expires_at)}). "
                    f"Use the new key for further rotations."
                )}},
                status_code=400,
            )
        else:
            # Grace period expired - key is effectively dead
            return JSONResponse(
                content={"error": {"code": "KEY_EXPIRED", "message": (
                    "This key's grace period has expired and it is no longer valid. "
                    "Use the new key that was created when this key was rotated."
                )}},
                status_code=400,
            )

    key_type = getattr(record, "key_type", "live") or "live"

    # Generate new key once with the correct prefix - do NOT generate twice.
    # A second generate_api_key() call would orphan the first hash in the DB.
    new_api_key = generate_api_key(key_type)
    new_key_id  = generate_key_id()
    new_hash    = _hash_key(new_api_key)

    # Calculate grace period expiry for old key (aware UTC; column is TIMESTAMPTZ)
    grace_expires = utc_now() + timedelta(minutes=body.grace_period_minutes)

    # Create new key with same metadata - key_type is preserved on rotation.
    #
    # The source-network restriction carries too. Rotation is a security action,
    # often taken because a credential is suspected compromised, so dropping the
    # restriction here would remove a control at the exact moment someone is
    # tightening things, and the new key would work from anywhere without anyone
    # being told. An operator who wants the replacement unrestricted clears it
    # afterwards, which is a deliberate act that leaves its own record.
    carried_allowlist = list(record.ip_allowlist or []) or None
    new_record = await repo.create({
        "key_id":       new_key_id,
        "name":         record.name,
        "key_hash":     new_hash,
        "key_type":     key_type,
        "is_admin":     record.is_admin,
        "revoked":      False,
        "app_id":       record.app_id,
        "dept_id":      record.dept_id,
        "tenant_id":    record.tenant_id,
        "ip_allowlist": carried_allowlist,
    })

    # Set old key to expire at end of grace period - both changes in one commit
    record.expires_at = grace_expires
    await db.commit()

    # Record that the restriction moved to the replacement. Without this a
    # restriction could appear on a credential with nothing saying how it got
    # there, and its absence after a rotation would be equally unexplained.
    if carried_allowlist:
        await _record_allowlist_change(
            db, request, principal, new_key_id, record.dept_id,
            previous=None, current=carried_allowlist,
        )

    return JSONResponse(content={
        "new_key_id":       new_key_id,
        "new_api_key":      new_api_key,
        "old_key_id":       key_id,
        "old_expires_at":   to_iso_z(grace_expires),
        "grace_period_minutes": body.grace_period_minutes,
        "name":             record.name,
        "app_id":           str(record.app_id)    if record.app_id    else None,
        "dept_id":          str(record.dept_id)   if record.dept_id   else None,
        "created_at":       to_iso_z(new_record.created_at),
        "message":          f"New key created. Old key expires in {body.grace_period_minutes} minutes.",
    }, status_code=201)