from datetime import datetime, timezone
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from api.v1.endpoints.ai import _request_store
from errors.exceptions import NotFoundError

router = APIRouter()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@router.get("/logs")
async def get_audit_logs(
    tenant_id:       str | None = Query(None),
    decision:        str | None = Query(None),
    threat_category: str | None = Query(None),
    from_:           str | None = Query(None, alias="from"),
    to:              str | None = Query(None),
    limit:           int        = Query(50, ge=1, le=500),
    offset:          int        = Query(0, ge=0),
):
    items = list(_request_store.values())

    # Filters
    if tenant_id:
        items = [i for i in items if i.get("tenant_id") == tenant_id]

    if decision:
        items = [i for i in items if i.get("decision") == decision.upper()]

    if threat_category:
        items = [
            i for i in items
            if threat_category.upper() in i.get("threats", [])
        ]

    from_dt = _parse_dt(from_)
    to_dt   = _parse_dt(to)

    if from_dt or to_dt:
        filtered = []
        for i in items:
            ts = i.get("timestamp")
            if not ts:
                filtered.append(i)
                continue
            try:
                item_dt = datetime.fromisoformat(ts)
                if from_dt and item_dt < from_dt:
                    continue
                if to_dt and item_dt > to_dt:
                    continue
                filtered.append(i)
            except ValueError:
                filtered.append(i)
        items = filtered

    total      = len(items)
    paginated  = items[offset: offset + limit]

    return JSONResponse(content={
        "total": total,
        "items": paginated,
    })


@router.get("/stats")
async def get_audit_stats(
    tenant_id: str | None = Query(None),
    from_:     str | None = Query(None, alias="from"),
    to:        str | None = Query(None),
):
    items = list(_request_store.values())

    if tenant_id:
        items = [i for i in items if i.get("tenant_id") == tenant_id]

    from_dt = _parse_dt(from_)
    to_dt   = _parse_dt(to)

    if not items:
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

    total    = len(items)
    blocked  = sum(1 for i in items if i.get("decision") == "BLOCK")
    sanitized = sum(1 for i in items if i.get("decision") == "SANITIZE")
    allowed  = sum(1 for i in items if i.get("decision") == "ALLOW")

    latencies = sorted([i.get("latency_ms", 0) for i in items])
    avg_lat   = sum(latencies) / len(latencies) if latencies else 0.0
    p95_idx   = int(len(latencies) * 0.95)
    p95_lat   = latencies[p95_idx] if latencies else 0.0

    # Threat distribution
    threat_counts: dict[str, int] = {}
    for item in items:
        for threat in item.get("threats", []):
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
        "block_rate":     round(blocked   / total, 4),
        "sanitize_rate":  round(sanitized / total, 4),
        "allow_rate":     round(allowed   / total, 4),
        "avg_latency_ms": round(avg_lat, 2),
        "p95_latency_ms": round(p95_lat, 2),
        "top_threats":    top_threats,
    })