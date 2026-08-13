# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Agent-run timeline endpoint (v1.7.0).

`GET /v1/agent-runs/{run_id}` returns every scan belonging to one agent run
(shared run_id), ordered as a timeline (turn_index, then created_at). Read-only,
derived from audit_logs; tenant/dept-scoped exactly like the rest of the audit
surface, so a run_id from another tenant returns an empty timeline, never another
tenant's rows. (Session-level grouping -- a conversation spanning multiple runs
-- is a later route; the repository query already supports it.)

Modeled as a first-class agentic resource (`/v1/agent-runs`) rather than an
audit sub-path, aligned with OpenTelemetry GenAI / LangSmith / OpenAI-Assistants
run semantics. Reuses the audit repository, scope, and item formatter.
"""

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal
from api.v1.dependencies.db import get_db
from api.v1.dependencies.scope import get_audit_scope
from api.v1.endpoints.audit import _enrich, _format_item
from db.repositories.audit import AuditRepository
from domain.entities.principal import Principal

router = APIRouter()


@router.get("/{run_id}")
async def get_agent_run(
    run_id:     str,
    request:    Request,
    limit:      int          = Query(500, ge=1, le=1000),
    db:         AsyncSession  = Depends(get_db),
    _principal: Principal     = Depends(get_current_principal),
):
    """Return one agent run's scans as an ordered timeline.

    Tenant/dept-scoped: non-admin principals only ever see runs within their own
    tenant (and department); a run_id outside that scope yields an empty
    timeline rather than another tenant's data.
    """
    scope     = get_audit_scope(request)
    tenant_id = scope.get("tenant_id")
    dept_id   = scope.get("dept_id")

    repo  = AuditRepository(db)
    items = await repo.list_run(
        run_id    = run_id,
        tenant_id = tenant_id,
        dept_id   = dept_id,
        limit     = limit,
    )

    dept_names, app_names, proxy_map = await _enrich(db, items)
    turns = [_format_item(i, dept_names, app_names, proxy_map) for i in items]

    return JSONResponse(content={
        "run_id": run_id,
        "count":  len(turns),
        "turns":  turns,
    })
