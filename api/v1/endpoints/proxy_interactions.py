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
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal
from api.v1.dependencies.db import get_db
from api.v1.schemas.response import (
    ErrorEnvelope,
    ProxyInteractionDetail,
    ProxyInteractionsResponse,
)
from db.models import ProxyInteractionModel
from db.repositories.proxy_interaction import ProxyInteractionRepository
from domain.entities.principal import Principal
from errors.exceptions import NotFoundError
from services.time import to_iso_z

router = APIRouter()
logger = logging.getLogger("wrapsec.proxy.interactions")

# Reachable failures. 422 is declared because the runtime handler returns the
# catalog envelope for a request-validation failure -- `?limit=abc` on the list
# route -- while FastAPI's generated entry described a shape this application
# never emits.
_INTERACTION_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Missing or invalid credentials."},
    422: {"model": ErrorEnvelope, "description": "A query parameter could not be parsed."},
}

# Only the DETAIL route has a 404. The list route answers an empty result with
# `{"total": 0, "items": []}`, so declaring one there would document a status it
# never produces.
#
# The description says "or is out of scope" on purpose: the route answers both
# with the same body, and a contract that promised 404 meant only "absent" would
# invite a caller to read it as proof of non-existence.
_INTERACTION_DETAIL_ERRORS: dict[int | str, dict[str, Any]] = {
    **_INTERACTION_ERRORS,
    404: {"model": ErrorEnvelope, "description": "No interaction with this trace_id, or it is out of the caller's scope. The two are deliberately indistinguishable."},
}


def _serialize(item: ProxyInteractionModel, detail: bool = False) -> dict:
    base = {
        "id":                    str(item.id),
        "trace_id":              item.trace_id,
        "created_at":            to_iso_z(item.created_at) if item.created_at else None,
        "key_id":                item.key_id.removeprefix("key:") if item.key_id else None,
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


@router.get(
    "/interactions",
    response_model               = ProxyInteractionsResponse,
    # The convention. Nothing in this projection is conditionally absent, so the
    # flag changes no output here; it keeps the family consistent and stays
    # correct if an optional field is ever added.
    response_model_exclude_unset = True,
    responses                    = _INTERACTION_ERRORS,
)
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

    # A value, not a JSONResponse: a Response object bypasses the response model.
    return {
        "total":  total,
        "limit":  limit,
        "offset": offset,
        "items":  [_serialize(item) for item in items],
    }


@router.get(
    "/interactions/{trace_id}",
    response_model               = ProxyInteractionDetail,
    response_model_exclude_unset = True,
    responses                    = _INTERACTION_DETAIL_ERRORS,
)
async def get_proxy_interaction(
    trace_id:   str,
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    repo = ProxyInteractionRepository(db)
    item = await repo.get_by_trace_id(trace_id)

    # All three 404 branches raise the SAME error with the SAME arguments, which
    # is the security property this route depends on: a caller must not be able
    # to distinguish "no such interaction" from "exists, but not yours". The
    # handler resolves the message from the catalog using only `resource`, a
    # constant, so the three bodies are identical by construction rather than by
    # a shared local that a later edit could diverge.
    #
    # The trace_id is deliberately NOT in the user-facing message. It travels in
    # `debug_message`, which is logged and never serialized, and the caller
    # correlates on the envelope's own trace_id -- the same treatment
    # `GET /v1/ai/requests/{trace_id}` already gives an identical lookup.
    if not item:
        raise NotFoundError(resource="interaction", identifier=trace_id)

    if request.state.is_admin:
        # Admin: the interaction must belong to this tenant. Check the stored
        # tenant_id directly (M5) - no api_keys resolution, so a revoked/deleted
        # key does not hide its own history.
        if not item.tenant_id or str(item.tenant_id) != request.state.tenant_id:
            raise NotFoundError(resource="interaction", identifier=trace_id)
    else:
        # Non-admin: must own the interaction. Interactions with no key_id are
        # system/admin records - never accessible to non-admin callers.
        if not item.key_id or item.key_id != request.state.key_id:
            raise NotFoundError(resource="interaction", identifier=trace_id)

    return _serialize(item, detail=True)