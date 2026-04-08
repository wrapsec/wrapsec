from datetime import datetime, timezone
from fastapi import APIRouter, Query, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.db import get_db
from db.repositories.audit import AuditRepository

router = APIRouter()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _format_item(item) -> dict:
    return {
        "trace_id":       item.trace_id,
        "timestamp":      item.created_at.isoformat(),
        "tenant_id":      item.tenant_id,
        "decision":       item.decision,
        "risk_score":     item.risk_score,
        "threats":        item.threats or [],
        "input_hash":     item.input_hash,
        "detection_mode": item.detection_mode,
        "execution_mode": item.execution_mode,
        "latency_ms":     item.latency_ms,
    }


@router.get("/logs")
async def get_audit_logs(
    tenant_id:       str | None = Query(None),
    trace_id:        str | None = Query(None),
    decision:        str | None = Query(None),
    threat_category: str | None = Query(None),
    from_:           str | None = Query(None, alias="from"),
    to:              str | None = Query(None),
    sort_by:         str        = Query("created_at"),
    sort_order:      str        = Query("desc"),
    limit:           int        = Query(50, ge=1, le=500),
    offset:          int        = Query(0, ge=0),
    db:              AsyncSession = Depends(get_db),
):
    repo = AuditRepository(db)
    total, items = await repo.list(
        tenant_id       = tenant_id,
        trace_id        = trace_id,
        decision        = decision,
        threat_category = threat_category,
        from_dt         = _parse_dt(from_),
        to_dt           = _parse_dt(to),
        sort_by         = sort_by,
        sort_order      = sort_order,
        limit           = limit,
        offset          = offset,
    )

    return JSONResponse(content={
        "total": total,
        "items": [_format_item(i) for i in items],
    })


@router.get("/stats")
async def get_audit_stats(
    tenant_id: str | None = Query(None),
    from_:     str | None = Query(None, alias="from"),
    to:        str | None = Query(None),
    db:        AsyncSession = Depends(get_db),
):
    repo  = AuditRepository(db)
    stats = await repo.get_stats(
        tenant_id = tenant_id,
        from_dt   = _parse_dt(from_),
        to_dt     = _parse_dt(to),
    )

    total = stats["total"]
    if total == 0:
        return JSONResponse(content={
            "period_from":    from_ or datetime.now(timezone.utc).isoformat(),
            "period_to":      to    or datetime.now(timezone.utc).isoformat(),
            "total_requests": 0,
            "block_rate":     0.0,
            "sanitize_rate":  0.0,
            "allow_rate":     0.0,
            "avg_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
            "top_threats":    [],
        })

    latencies = stats["latencies"]
    avg_lat   = sum(latencies) / len(latencies) if latencies else 0.0
    p95_idx   = int(len(latencies) * 0.95)
    p95_lat   = latencies[p95_idx] if latencies else 0.0

    threat_counts: dict[str, int] = {}
    for threat in stats["threats"]:
        threat_counts[threat] = threat_counts.get(threat, 0) + 1

    top_threats = sorted(
        [{"category": k, "count": v} for k, v in threat_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    return JSONResponse(content={
        "period_from":    from_ or datetime.now(timezone.utc).isoformat(),
        "period_to":      to    or datetime.now(timezone.utc).isoformat(),
        "total_requests": total,
        "block_rate":     round(stats["block_count"]    / total, 4),
        "sanitize_rate":  round(stats["sanitize_count"] / total, 4),
        "allow_rate":     round(stats["allow_count"]    / total, 4),
        "avg_latency_ms": round(avg_lat, 2),
        "p95_latency_ms": round(p95_lat, 2),
        "top_threats":    top_threats,
    })