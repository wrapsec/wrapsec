import time
import hashlib
from fastapi import APIRouter, Request, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.schemas.request import AIRequestSchema
from api.v1.dependencies.db import get_db
from db.repositories.audit import AuditRepository
from config.settings import get_settings
from domain.enums import DecisionType, DetectionMode, ExecutionMode
from domain.value_objects.trace_id import TraceId
from domain.entities.request import (
    IncomingRequest, RequestMetadata,
    RequestContext, RequestOptions
)
from errors.exceptions import NotFoundError, DebugForbiddenError
from services.gateway.service import GatewayService

router   = APIRouter()
settings = get_settings()
_gateway = GatewayService()


def _build_response(decision, debug: bool = False) -> dict:
    response = {
        "trace_id":        str(decision.trace_id),
        "decision":        decision.decision.value,
        "risk_score":      decision.risk_score.value,
        "threats":         [t.value for t in decision.threats],
        "sanitized_input": decision.sanitized_input,
        "output":          decision.output,
        "processing": {
            "latency_ms":     round(decision.latency_ms, 2),
            "llm_invoked":    decision.llm_invoked,
            "detection_mode": decision.detection_mode.value if hasattr(decision.detection_mode, "value") else decision.detection_mode,
            "execution_mode": decision.execution_mode.value if hasattr(decision.execution_mode, "value") else decision.execution_mode,
        },
    }

    if debug and decision.layer_scores:
        def layer_decision(score: float) -> str:
            if score >= settings.block_threshold:
                return DecisionType.BLOCK.value
            if score >= settings.sanitize_threshold:
                return DecisionType.SANITIZE.value
            return DecisionType.ALLOW.value

        response["debug"] = {
            "rule_score": decision.layer_scores.rule_score,
            "ml_score":   decision.layer_scores.ml_score,
            "llm_score":  decision.layer_scores.llm_score,
            "layer_decisions": {
                "rule": layer_decision(decision.layer_scores.rule_score),
                "ml":   layer_decision(decision.layer_scores.ml_score),
                "llm":  layer_decision(decision.layer_scores.llm_score),
            }
        }

    return response


@router.post("/request", response_model=None)
async def ai_request(
    body:    AIRequestSchema,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    if body.options.debug and not getattr(request.state, "is_admin", False):
        raise DebugForbiddenError()

    incoming = IncomingRequest(
        input          = body.input,
        detection_mode = DetectionMode(body.detection_mode),
        execution_mode = ExecutionMode(body.execution_mode),
        model          = body.model,
        metadata       = RequestMetadata(
            tenant_id = body.metadata.tenant_id if body.metadata else None,
            source    = body.metadata.source if body.metadata else None,
            user_id   = body.metadata.user_id if body.metadata else None,
        ),
        context        = RequestContext(
            user_role   = body.context.user_role if body.context else None,
            sensitivity = body.context.sensitivity if body.context else None,
        ),
        options        = RequestOptions(
            stream = body.options.stream if body.options else False,
            debug  = body.options.debug if body.options else False,
        ),
    )

    result = await run_in_threadpool(_gateway.process, incoming)

    # Persist audit log to PostgreSQL
    repo = AuditRepository(db)
    await repo.create({
        "trace_id":       str(incoming.trace_id),
        "decision":       result.decision.decision.value,
        "risk_score":     result.decision.risk_score.value,
        "threats":        [t.value for t in result.decision.threats],
        "input_hash":     result.audit_log.input_hash,
        "detection_mode": body.detection_mode,
        "execution_mode": body.execution_mode,
        "llm_invoked":    result.decision.llm_invoked,
        "latency_ms":     round(result.decision.latency_ms, 2),
        "tenant_id":      body.metadata.tenant_id if body.metadata else None,
        "source":         body.metadata.source if body.metadata else None,
        "user_id":        body.metadata.user_id if body.metadata else None,
    })

    response = _build_response(
        result.decision,
        debug=body.options.debug and getattr(request.state, "is_admin", False)
    )

    return JSONResponse(content=response)


@router.get("/requests/{trace_id}")
async def get_request(
    trace_id: str,
    db:       AsyncSession = Depends(get_db),
):
    repo   = AuditRepository(db)
    record = await repo.get_by_trace_id(trace_id)

    if not record:
        raise NotFoundError("request", trace_id)

    return JSONResponse(content={
        "trace_id":       record.trace_id,
        "timestamp":      record.created_at.isoformat(),
        "metadata": {
            "tenant_id": record.tenant_id,
            "source":    record.source,
            "user_id":   record.user_id,
        },
        "decision":       record.decision,
        "risk_score":     record.risk_score,
        "threats":        record.threats or [],
        "input_hash":     record.input_hash,
        "processing": {
            "latency_ms":     record.latency_ms,
            "llm_invoked":    record.llm_invoked,
            "detection_mode": record.detection_mode,
            "execution_mode": record.execution_mode,
        },
    })