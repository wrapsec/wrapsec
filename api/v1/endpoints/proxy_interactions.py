"""
Proxy interactions read endpoints.

GET /v1/proxy/interactions          -- list proxy interactions (paginated)
GET /v1/proxy/interactions/:trace_id -- get single interaction detail
"""

import logging
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.db import get_db
from db.repositories.proxy_interaction import ProxyInteractionRepository
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
):
    limit  = min(max(1, limit), 200)
    offset = max(0, offset)

    repo         = ProxyInteractionRepository(db)
    items, total = await repo.list(
        key_id           = None,   # admin sees all; scope by key_id for non-admin if needed
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
    trace_id: str,
    db:       AsyncSession = Depends(get_db),
):
    repo   = ProxyInteractionRepository(db)
    item   = await repo.get_by_trace_id(trace_id)

    if not item:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": f"Interaction {trace_id} not found."}},
        )

    return JSONResponse(content=_serialize(item, detail=True))