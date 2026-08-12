# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Email delivery audit endpoints (v1.8.3).

A read-only, tenant-scoped view of email delivery status for operational and
security troubleshooting -- not an email-content archive. Exposes metadata only
(no subject, body, or MIME): what was attempted, to whom, in which
tenant/department context, when, its status, attempts, and why it failed.

Access is Admin or Auditor (interim RBAC per the plan). Every query is scoped to
the caller's tenant; cross-tenant ids return 404. Recipient addresses are
returned in full to these authorized roles and masked in the dashboard display.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import require_role
from api.v1.dependencies.db import get_db
from db.models import EmailOutboxModel
from db.repositories.email_outbox import EmailOutboxRepository
from domain.entities.principal import Principal
from domain.enums import EmailStatus
from errors.exceptions import NotFoundError, ValidationError
from services.time import parse_utc_iso, to_iso_z

router = APIRouter()

# Admin and Auditor may read the tenant's email delivery audit (interim RBAC).
_require_email_audit = require_role("ADMIN", "AUDITOR")


def _completed_at(row: EmailOutboxModel):
    """Terminal completion time: acceptance time for accepted rows, the terminal
    transition time for failed rows, otherwise None (still in flight)."""
    if row.status == EmailStatus.PROVIDER_ACCEPTED.value:
        return row.sent_at
    if row.status == EmailStatus.FAILED.value:
        return row.updated_at
    return None


def _format(row: EmailOutboxModel) -> dict:
    """Metadata only -- no subject, body, or MIME (delivery audit, not content)."""
    completed = _completed_at(row)
    return {
        "id":                  str(row.id),
        "tenant_id":           str(row.tenant_id)     if row.tenant_id     else None,
        "department_id":       str(row.department_id) if row.department_id else None,
        "user_id":             str(row.user_id)       if row.user_id       else None,
        "notification_type":   row.notification_type,
        "recipient":           row.recipient,
        "locale":              row.locale,
        "status":              row.status,
        "attempt_count":       row.attempt_count,
        "provider_message_id": row.provider_message_id,
        "trace_id":            row.trace_id,
        "last_error":          row.last_error,
        "created_at":          to_iso_z(row.created_at) if row.created_at else None,
        "last_attempt_at":     to_iso_z(row.sending_at) if row.sending_at else None,
        "completed_at":        to_iso_z(completed)      if completed      else None,
    }


def _parse_filters(
    *,
    status:            str | None,
    notification_type: str | None,
    department_id:     str | None,
    created_from:      str | None,
    created_to:        str | None,
) -> dict:
    """Validate and normalize the shared query filters (raises 400 on bad input)."""
    if status is not None and status not in {s.value for s in EmailStatus}:
        raise ValidationError(
            f"Invalid status '{status}'. Must be one of: "
            f"{', '.join(s.value for s in EmailStatus)}."
        )
    dept_uuid = None
    if department_id:
        try:
            dept_uuid = uuid.UUID(department_id)
        except ValueError as exc:
            raise ValidationError(f"Invalid department_id '{department_id}'.") from exc
    try:
        cf = parse_utc_iso(created_from) if created_from else None
        ct = parse_utc_iso(created_to) if created_to else None
    except ValueError as exc:
        raise ValidationError("created_from/created_to must be ISO-8601 timestamps.") from exc
    return {
        "status":            status,
        "notification_type": notification_type,
        "department_id":     dept_uuid,
        "created_from":      cf,
        "created_to":        ct,
    }


@router.get("")
async def list_emails(
    request:           Request,
    status:            str | None = Query(None),
    notification_type: str | None = Query(None),
    department_id:     str | None = Query(None),
    recipient:         str | None = Query(None),
    created_from:      str | None = Query(None),
    created_to:        str | None = Query(None),
    limit:             int = Query(50, ge=1, le=200),
    offset:            int = Query(0, ge=0),
    principal:         Principal    = Depends(_require_email_audit),
    db:                AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    List email delivery rows for the caller's tenant, newest first.

    Filters: status, notification_type, department_id, recipient (substring),
    created_from / created_to (ISO-8601). Scoped to principal.tenant_id.

    Auth: JWT + ADMIN or AUDITOR role.
    """
    f = _parse_filters(
        status=status, notification_type=notification_type, department_id=department_id,
        created_from=created_from, created_to=created_to,
    )
    rows = await EmailOutboxRepository(db).list_by_tenant(
        tenant_id = uuid.UUID(str(principal.tenant_id)),
        limit=limit, offset=offset, recipient=recipient, **f,
    )
    return JSONResponse(content={"emails": [_format(r) for r in rows]})


@router.get("/summary")
async def email_summary(
    request:           Request,
    notification_type: str | None = Query(None),
    department_id:     str | None = Query(None),
    recipient:         str | None = Query(None),
    created_from:      str | None = Query(None),
    created_to:        str | None = Query(None),
    principal:         Principal    = Depends(_require_email_audit),
    db:                AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Per-status counts (queued / sending / provider_accepted / failed) for the
    caller's tenant, honoring the same filters as the listing (minus status).

    Auth: JWT + ADMIN or AUDITOR role.
    """
    f = _parse_filters(
        status=None, notification_type=notification_type, department_id=department_id,
        created_from=created_from, created_to=created_to,
    )
    f.pop("status")
    counts = await EmailOutboxRepository(db).count_by_status(
        tenant_id = uuid.UUID(str(principal.tenant_id)),
        recipient=recipient, **f,
    )
    return JSONResponse(content={"counts": counts})


@router.get("/{email_id}")
async def get_email(
    email_id:  uuid.UUID,
    principal: Principal    = Depends(_require_email_audit),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Return a single email delivery row by id.

    Returns 404 when the row does not exist OR belongs to another tenant, so
    cross-tenant ids are indistinguishable from missing ones.

    Auth: JWT + ADMIN or AUDITOR role.
    """
    row = await EmailOutboxRepository(db).get_by_id(email_id)
    if row is None or str(row.tenant_id) != str(principal.tenant_id):
        raise NotFoundError("email", str(email_id))
    return JSONResponse(content=_format(row))
