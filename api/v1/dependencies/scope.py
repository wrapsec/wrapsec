# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from __future__ import annotations
from typing import TYPE_CHECKING
from fastapi import Request

if TYPE_CHECKING:
    from db.models import AuditLogModel
    from db.repositories.audit import AuditRepository


def get_audit_scope(request: Request) -> dict:
    """
    Returns tenant/dept filter kwargs for the current principal's audit scope.

    Admin     : empty dict - caller-supplied query filters apply as-is.
    Non-admin : {"tenant_id": ..., "dept_id": ...} - identity always wins,
                any tenant_id/dept_id from the query string are ignored.

    Usage with repo.list() - admin query params pass through, non-admin are fixed:
        scope     = get_audit_scope(request)
        tenant_id = scope.get("tenant_id", tenant_id)
        dept_id   = scope.get("dept_id",   dept_id)
        await repo.list(tenant_id=tenant_id, dept_id=dept_id, ...)

    Usage with raw WHERE clauses:
        scope = get_audit_scope(request)
        if scope.get("tenant_id"):
            stmt = stmt.where(Model.tenant_id == scope["tenant_id"])
        if scope.get("dept_id"):
            stmt = stmt.where(Model.dept_id == scope["dept_id"])
    """
    if getattr(request.state, "is_admin", False):
        return {}
    return {
        "tenant_id": getattr(request.state, "tenant_id", None),
        "dept_id":   getattr(request.state, "dept_id",   None),
    }


async def get_scoped_audit_record(
    repo:     "AuditRepository",
    trace_id: str,
    request:  Request,
) -> "AuditLogModel | None":
    """
    Fetches a single audit record by trace_id, enforcing the principal's scope.

    Admin             : unscoped - can see any record.
    Non-admin + dept  : dept-scoped (primary path - all non-admin keys have dept_id).
    Non-admin no dept : tenant-scoped (defensive fallback for edge cases).
    """
    is_admin = getattr(request.state, "is_admin", False)
    dept_id  = getattr(request.state, "dept_id", None)

    if is_admin:
        return await repo.get_by_trace_id(trace_id)
    elif dept_id:
        return await repo.get_by_trace_id_scoped(trace_id, dept_id)
    else:
        tenant_id = getattr(request.state, "tenant_id", "")
        return await repo.get_by_trace_id_tenant_scoped(trace_id, tenant_id)
