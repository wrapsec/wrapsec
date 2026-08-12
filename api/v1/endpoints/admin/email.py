# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Email audit endpoints (v1.8.3).

A read-only, tenant-scoped view of the email outbox for operational and
security visibility: which notifications were produced, their delivery status,
attempt counts, and failure reasons.

Access is Admin or Auditor (interim RBAC per the plan, until the broader RBAC
hardening pass moves this to the canonical permission model). Every query is
scoped to the caller's tenant, so an admin can never read another tenant's
email records. Rendered bodies are deliberately NOT exposed: this is a delivery
audit, not a content/log viewer.
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
from services.time import to_iso_z

router = APIRouter()

# Admin and Auditor may read the tenant's email audit (interim RBAC).
_require_email_audit = require_role("ADMIN", "AUDITOR")


def _format(row: EmailOutboxModel) -> dict:
    """Metadata + subject only. Rendered bodies are never exposed."""
    return {
        "id":                  str(row.id),
        "notification_type":   row.notification_type,
        "recipient":           row.recipient,
        "tenant_id":           str(row.tenant_id) if row.tenant_id else None,
        "user_id":             str(row.user_id)   if row.user_id   else None,
        "locale":              row.locale,
        "subject":             row.subject,
        "status":              row.status,
        "attempt_count":       row.attempt_count,
        "provider_message_id": row.provider_message_id,
        "trace_id":            row.trace_id,
        "last_error":          row.last_error,
        "created_at":          to_iso_z(row.created_at)   if row.created_at   else None,
        "available_at":        to_iso_z(row.available_at) if row.available_at else None,
        "sending_at":          to_iso_z(row.sending_at)   if row.sending_at   else None,
        "sent_at":             to_iso_z(row.sent_at)      if row.sent_at      else None,
        "updated_at":          to_iso_z(row.updated_at)   if row.updated_at   else None,
    }


@router.get("")
async def list_emails(
    request:   Request,
    status:    str | None = Query(None),
    limit:     int = Query(50, ge=1, le=200),
    offset:    int = Query(0, ge=0),
    principal: Principal    = Depends(_require_email_audit),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    List email outbox rows for the caller's tenant, newest first.

    Optional `status` filter (queued | sending | provider_accepted | failed).
    Scoped to principal.tenant_id - never cross-tenant.

    Auth: JWT + ADMIN or AUDITOR role.
    """
    if status is not None and status not in {s.value for s in EmailStatus}:
        raise ValidationError(
            f"Invalid status '{status}'. Must be one of: "
            f"{', '.join(s.value for s in EmailStatus)}."
        )

    repo = EmailOutboxRepository(db)
    rows = await repo.list_by_tenant(
        tenant_id = uuid.UUID(str(principal.tenant_id)),
        status    = status,
        limit     = limit,
        offset    = offset,
    )
    return JSONResponse(content={"emails": [_format(r) for r in rows]})


@router.get("/{email_id}")
async def get_email(
    email_id:  uuid.UUID,
    principal: Principal    = Depends(_require_email_audit),
    db:        AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Return a single email outbox row by id.

    Returns 404 when the row does not exist OR belongs to another tenant, so
    cross-tenant ids are indistinguishable from missing ones.

    Auth: JWT + ADMIN or AUDITOR role.
    """
    row = await EmailOutboxRepository(db).get_by_id(email_id)
    if row is None or str(row.tenant_id) != str(principal.tenant_id):
        raise NotFoundError("email", str(email_id))
    return JSONResponse(content=_format(row))
