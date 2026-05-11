# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Proxy interactions read endpoints.

GET /v1/proxy/interactions          -- list proxy interactions (paginated)
GET /v1/proxy/interactions/:trace_id -- get single interaction detail
"""

import logging
import uuid
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal
from api.v1.dependencies.db import get_db
from domain.entities.principal import Principal
from db.repositories.proxy_interaction import ProxyInteractionRepository
from db.repositories.api_key import ApiKeyRepository
from db.models import ProxyInteractionModel

router = APIRouter()
logger = logging.getLogger("wrapsec.proxy.interactions")


def _serialize(item: ProxyInteractionModel, detail: bool = False) -> dict:
    base = {
        "id":                    str(item.id),
        "trace_id":              item.trace_id,
        "created_at":            item.created_at.isoformat() if item.created_at else None,
        "key_id":                item.key_id,
        "user_id":               item.user_id,
        "input_decision":        item.input_decision,
        "input_primary_reason":  item.input_primary_reason,
        "input_confidence":      item.input_confidence,
        "input_threats":         item.input_threats or [],
        "input_attack_type":     item.input_attack_type,
        "provider":              item.provider,
        "model":                 item.model,
        "provider_latency_ms":   item.provider_latency_ms,
        "execution_status":      item.execution_status,
        "output_decision":       item.output_decision,
        "output_primary_reason": item.output_primary_reason,
        "output_confidence":     item.output_confidence,
        "output_threats":        item.output_threats or [],
        "behavior_flag":         item.behavior_flag,
        "output_flags":          item.output_flags,
        "total_latency_ms":      item.total_latency_ms,
    }

    if detail:
        base["input_raw"]        = item.input_raw
        base["input_sanitized"]  = item.input_sanitized
        base["output_raw"]       = item.output_raw
        base["output_sanitized"] = item.output_sanitized

    return base


@router.get("/interactions")
async def list_proxy_interactions(
    request:          Request,
    execution_status: str | None = None,
    limit:            int = 50,
    offset:           int = 0,
    db:               AsyncSession = Depends(get_db),
    _principal:       Principal    = Depends(get_current_principal),
):
    limit  = min(max(1, limit), 200)
    offset = max(0, offset)

    tenant_id     = uuid.UUID(request.state.tenant_id) if request.state.tenant_id else None
    # Non-admin: further scope to their own key's interactions only.
    scoped_key_id = None if request.state.is_admin else request.state.key_id

    repo         = ProxyInteractionRepository(db)
    items, total = await repo.list(
        tenant_id        = tenant_id,
        key_id           = scoped_key_id,
        execution_status = execution_status,
        limit            = limit,
        offset           = offset,
    )

    return JSONResponse(content={
        "total":  total,
        "limit":  limit,
        "offset": offset,
        "items":  [_serialize(item) for item in items],
    })


@router.get("/interactions/{trace_id}")
async def get_proxy_interaction(
    trace_id:   str,
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    repo = ProxyInteractionRepository(db)
    item = await repo.get_by_trace_id(trace_id)

    not_found = JSONResponse(
        status_code=404,
        content={"error": {"code": "NOT_FOUND", "message": f"Interaction {trace_id} not found."}},
    )
    if not item:
        return not_found

    if request.state.is_admin:
        # Admin: verify the interaction's key belongs to this tenant
        if item.key_id:
            key_record = await ApiKeyRepository(db).get_by_key_id(item.key_id)
            if not key_record or str(key_record.tenant_id) != request.state.tenant_id:
                return not_found
    else:
        # Non-admin: must own the interaction. Interactions with no key_id are
        # system/admin records - never accessible to non-admin callers.
        if not item.key_id or item.key_id != request.state.key_id:
            return not_found

    return JSONResponse(content=_serialize(item, detail=True))