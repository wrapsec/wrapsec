# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request

if TYPE_CHECKING:
    from db.models import AuditLogModel
    from db.repositories.audit import AuditRepository


# The master admin API key uses the sentinel key_id "key:admin" (see
# api/v1/middleware/auth.py _authenticate_admin_key). Only that principal is
# cross-tenant by design; every other admin (tenant ADMIN role users) must be
# scoped to their own tenant_id to prevent Issue 162 style cross-tenant reads.
_MASTER_ADMIN_KEY_ID = "key:admin"


def _is_master_admin(request: Request) -> bool:
    return getattr(request.state, "key_id", None) == _MASTER_ADMIN_KEY_ID


def get_audit_scope(request: Request) -> dict:
    """
    Returns tenant/dept filter kwargs for the current principal's audit scope.

    Master admin key : empty dict - caller-supplied query filters apply as-is.
    Tenant admin     : {"tenant_id": ...} - identity always wins for tenant_id,
                       dept_id from the query string still applies.
    Non-admin        : {"tenant_id": ..., "dept_id": ...} - both fixed.

    Usage with repo.list() - non-admin scopes are enforced, admin dept filter
    still passes through:

        scope     = get_audit_scope(request)
        tenant_id = scope.get("tenant_id", tenant_id)
        dept_id   = scope.get("dept_id",   dept_id)
        await repo.list(tenant_id=tenant_id, dept_id=dept_id, ...)
    """
    if _is_master_admin(request):
        return {}

    scope: dict = {"tenant_id": getattr(request.state, "tenant_id", None)}
    if not getattr(request.state, "is_admin", False):
        scope["dept_id"] = getattr(request.state, "dept_id", None)
    return scope


async def get_scoped_audit_record(
    repo:     AuditRepository,
    trace_id: str,
    request:  Request,
) -> AuditLogModel | None:
    """
    Fetches a single audit record by trace_id, enforcing the principal's scope.

    Master admin key  : unscoped - can see any record.
    Tenant admin      : tenant-scoped (Issue 162 - prevents cross-tenant reads).
    Non-admin + dept  : dept-scoped (primary path - all non-admin keys have dept_id).
    Non-admin no dept : tenant-scoped (defensive fallback for edge cases).
    """
    if _is_master_admin(request):
        return await repo.get_by_trace_id(trace_id)

    is_admin  = getattr(request.state, "is_admin", False)
    tenant_id = getattr(request.state, "tenant_id", "") or ""
    dept_id   = getattr(request.state, "dept_id", None)

    if is_admin:
        return await repo.get_by_trace_id_tenant_scoped(trace_id, tenant_id)
    if dept_id:
        return await repo.get_by_trace_id_scoped(trace_id, dept_id, tenant_id)
    return await repo.get_by_trace_id_tenant_scoped(trace_id, tenant_id)
