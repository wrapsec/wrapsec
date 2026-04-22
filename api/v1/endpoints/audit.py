from datetime import datetime, timezone
from fastapi import APIRouter, Query, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, case, Integer
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.db import get_db
from db.repositories.audit import AuditRepository
from db.models import AuditLogModel

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
        "trace_id":              item.trace_id,
        "timestamp":             item.created_at.isoformat(),
        "tenant_id":             item.tenant_id,
        "decision":              item.decision,
        "primary_reason":        item.primary_reason,
        "risk_score":            item.risk_score,
        "confidence":            item.confidence,
        "confidence_band":       item.confidence_band,
        "threats":               item.threats or [],
        "input_hash":            item.input_hash,
        "detection_mode":        item.detection_mode,
        "execution_mode":        item.execution_mode,
        "latency_ms":            item.latency_ms,
        "key_id":                item.key_id,
        "dept_id":               item.dept_id,
        "app_id":                item.app_id,
        "user_id":               item.user_id,
        "source":                item.source,
        "ip_address":            item.ip_address,
        "attribution_verified":  item.attribution_verified,
        "policy_source":         item.policy_source,
        "input_length":          item.input_length or 0,
    }


@router.get("/logs")
async def get_audit_logs(
    request:         Request,
    tenant_id:       str | None = Query(None),
    dept_id:         str | None = Query(None),
    app_id:          str | None = Query(None),
    key_id:          str | None = Query(None),
    user_id:         str | None = Query(None),
    source:          str | None = Query(None),
    trace_id:        str | None = Query(None),
    decision:        str | None = Query(None),
    threat_category: str | None = Query(None),
    primary_reason:  str | None = Query(None),
    confidence_band: str | None = Query(None),
    execution_mode:  str | None = Query(None),
    from_:           str | None = Query(None, alias="from"),
    to:              str | None = Query(None),
    sort_by:         str        = Query("created_at"),
    sort_order:      str        = Query("desc"),
    limit:           int        = Query(50, ge=1, le=500),
    offset:          int        = Query(0, ge=0),
    db:              AsyncSession = Depends(get_db),
):
    is_admin = getattr(request.state, "is_admin", False)
    # Non-admin keys are always scoped to their own dept.
    # Ignore any dept_id query param from the caller — use identity from auth.
    if not is_admin:
        dept_id   = getattr(request.state, "dept_id",   None)
        tenant_id = getattr(request.state, "tenant_id", None)

    repo = AuditRepository(db)
    total, items = await repo.list(
        tenant_id       = tenant_id,
        dept_id         = dept_id,
        app_id          = app_id,
        key_id          = key_id,
        user_id         = user_id,
        execution_mode  = execution_mode,
        source          = source,
        trace_id        = trace_id,
        decision        = decision,
        threat_category = threat_category,
        primary_reason  = primary_reason,
        confidence_band = confidence_band,
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
    request:   Request,
    tenant_id: str | None = Query(None),
    from_:     str | None = Query(None, alias="from"),
    to:        str | None = Query(None),
    db:        AsyncSession = Depends(get_db),
):
    is_admin = getattr(request.state, "is_admin", False)
    if not is_admin:
        tenant_id = getattr(request.state, "tenant_id", None)

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

@router.get("/attribution")
async def get_attribution_report(
    request:    Request,
    dept_id:    str | None = Query(None),
    limit:      int        = Query(10, ge=1, le=100),
    db:         AsyncSession = Depends(get_db),
):
    """
    Returns attribution summary — requests grouped by key, department,
    and application. Useful for security review and capacity planning.
    Extensible: add group_by parameter in v1.1 for custom grouping.
    """
    from sqlalchemy import select as sa_select

    is_admin = getattr(request.state, "is_admin", False)
    if not is_admin:
        dept_id = getattr(request.state, "dept_id", None)

    base_where = []
    if dept_id:
        base_where.append(AuditLogModel.dept_id == dept_id)

    # By API key
    key_query = sa_select(
        AuditLogModel.key_id,
        AuditLogModel.source,
        func.count().label("total"),
        func.sum(
            case((AuditLogModel.decision == "BLOCK", 1), else_=0)
        ).label("blocked"),
        func.avg(AuditLogModel.latency_ms).label("avg_latency"),
    ).where(*base_where).group_by(
        AuditLogModel.key_id,
        AuditLogModel.source,
    ).order_by(func.count().desc()).limit(limit)

    key_result = await db.execute(key_query)
    by_key = [
        {
            "key_id":       row.key_id,
            "source":       row.source,
            "total":        row.total,
            "blocked":      row.blocked or 0,
            "block_rate":   round((row.blocked or 0) / row.total, 3),
            "avg_latency_ms": round(row.avg_latency or 0, 2),
        }
        for row in key_result
    ]

    # By department — scoped to same dept filter as rest of attribution
    dept_query = sa_select(
        AuditLogModel.dept_id,
        func.count().label("total"),
        func.sum(
            case((AuditLogModel.decision == "BLOCK", 1), else_=0)
        ).label("blocked"),
    ).where(*base_where).group_by(AuditLogModel.dept_id).order_by(
        func.count().desc()
    ).limit(limit)

    dept_result = await db.execute(dept_query)
    by_dept = [
        {
            "dept_id":    row.dept_id,
            "total":      row.total,
            "blocked":    row.blocked or 0,
            "block_rate": round((row.blocked or 0) / row.total, 3),
        }
        for row in dept_result
    ]

    # By application
    app_query = sa_select(
        AuditLogModel.app_id,
        func.count().label("total"),
        func.sum(
            case((AuditLogModel.decision == "BLOCK", 1), else_=0)
        ).label("blocked"),
        func.avg(AuditLogModel.latency_ms).label("avg_latency"),
    ).where(*base_where).group_by(
        AuditLogModel.app_id,
    ).order_by(func.count().desc()).limit(limit)

    app_result = await db.execute(app_query)
    by_app = [
        {
            "app_id":       row.app_id,
            "total":        row.total,
            "blocked":      row.blocked or 0,
            "block_rate":   round((row.blocked or 0) / row.total, 3),
            "avg_latency_ms": round(row.avg_latency or 0, 2),
        }
        for row in app_result
    ]

    # By primary reason
    reason_query = sa_select(
        AuditLogModel.primary_reason,
        func.count().label("total"),
    ).where(*base_where).group_by(
        AuditLogModel.primary_reason,
    ).order_by(func.count().desc())

    reason_result = await db.execute(reason_query)
    by_reason = [
        {"primary_reason": row.primary_reason, "count": row.total}
        for row in reason_result
        if row.primary_reason
    ]

    # By confidence band
    band_query = sa_select(
        AuditLogModel.confidence_band,
        func.count().label("total"),
    ).where(*base_where).group_by(
        AuditLogModel.confidence_band,
    ).order_by(func.count().desc())

    band_result = await db.execute(band_query)
    by_confidence = [
        {"band": row.confidence_band, "count": row.total}
        for row in band_result
        if row.confidence_band
    ]

    return JSONResponse(content={
        "by_key":        by_key,
        "by_department": by_dept,
        "by_application": by_app,
        "by_primary_reason": by_reason,
        "by_confidence_band": by_confidence,
    })

@router.get("/analytics")
async def get_analytics(
    request:    Request,
    from_date:  str | None = Query(None, alias="from"),
    to_date:    str | None = Query(None, alias="to"),
    group_by:   str        = Query("day", pattern="^(hour|day|week|month)$"),
    dept_id:    str | None = Query(None),
    db:         AsyncSession = Depends(get_db),
):
    """
    Advanced cross-department analytics with time-series trend data.
    Groups requests by time period with decision breakdowns.
    """
    from sqlalchemy import select, func
    from db.models import AuditLogModel
    from datetime import datetime, timezone

    is_admin = getattr(request.state, "is_admin", False)
    if not is_admin:
        dept_id = getattr(request.state, "dept_id", None)

    # Build base query
    stmt = select(
        func.date_trunc(group_by, AuditLogModel.created_at).label("period"),
        AuditLogModel.decision,
        func.count().label("count"),
        func.avg(AuditLogModel.risk_score).label("avg_risk_score"),
        func.avg(AuditLogModel.latency_ms).label("avg_latency_ms"),
    )

    # Apply filters — always scoped for non-admin keys
    if dept_id:
        stmt = stmt.where(AuditLogModel.dept_id == dept_id)
    if from_date:
        try:
            dt   = datetime.fromisoformat(from_date).replace(tzinfo=None)
            stmt = stmt.where(AuditLogModel.created_at >= dt)
        except ValueError:
            pass
    if to_date:
        try:
            dt   = datetime.fromisoformat(to_date + "T23:59:59").replace(tzinfo=None)
            stmt = stmt.where(AuditLogModel.created_at <= dt)
        except ValueError:
            pass

    stmt   = stmt.group_by("period", AuditLogModel.decision).order_by("period")
    result = await db.execute(stmt)
    rows   = result.fetchall()

    # Aggregate into time-series
    periods: dict = {}
    for row in rows:
        period_str = row.period.isoformat() if row.period else "unknown"
        if period_str not in periods:
            periods[period_str] = {
                "period":         period_str,
                "total":          0,
                "blocked":        0,
                "sanitized":      0,
                "allowed":        0,
                "avg_risk_score": 0.0,
                "avg_latency_ms": 0.0,
            }
        periods[period_str]["total"]          += row.count
        periods[period_str]["avg_risk_score"]  = round(float(row.avg_risk_score or 0), 3)
        periods[period_str]["avg_latency_ms"]  = round(float(row.avg_latency_ms or 0), 2)

        if row.decision == "BLOCK":
            periods[period_str]["blocked"]   += row.count
        elif row.decision == "SANITIZE":
            periods[period_str]["sanitized"] += row.count
        elif row.decision == "ALLOW":
            periods[period_str]["allowed"]   += row.count

    # Compute block_rate per period
    trend = []
    for p in periods.values():
        p["block_rate"] = round(p["blocked"] / p["total"], 3) if p["total"] > 0 else 0.0
        trend.append(p)

    total_requests = sum(p["total"]   for p in trend)
    total_blocked  = sum(p["blocked"] for p in trend)

    return JSONResponse(content={
        "group_by":   group_by,
        "dept_id":    dept_id,
        "from":       from_date,
        "to":         to_date,
        "total":      total_requests,
        "block_rate": round(total_blocked / total_requests, 3) if total_requests > 0 else 0.0,
        "trend":      trend,
    })

@router.get("/export")
async def export_audit_logs(
    request:         Request,
    dept_id:         str | None = Query(None),
    app_id:          str | None = Query(None),
    decision:        str | None = Query(None),
    primary_reason:  str | None = Query(None),
    confidence_band: str | None = Query(None),
    from_:           str | None = Query(None, alias="from"),
    to:              str | None = Query(None),
    limit:           int        = Query(1000, ge=1, le=10000),
    db:              AsyncSession = Depends(get_db),
):
    is_admin = getattr(request.state, "is_admin", False)
    if not is_admin:
        dept_id = getattr(request.state, "dept_id", None)
    """
    Export audit logs as CSV for compliance reporting.
    Extensible: additional filters and formats (JSON, PDF) in v1.1.
    """
    import csv
    import io
    from starlette.responses import StreamingResponse

    repo = AuditRepository(db)
    _, items = await repo.list(
        dept_id         = dept_id,
        app_id          = app_id,
        decision        = decision,
        primary_reason  = primary_reason,
        confidence_band = confidence_band,
        from_dt         = _parse_dt(from_),
        to_dt           = _parse_dt(to),
        sort_by         = "created_at",
        sort_order      = "desc",
        limit           = limit,
        offset          = 0,
    )

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "trace_id", "timestamp", "decision", "risk_score",
        "confidence", "confidence_band", "primary_reason",
        "threats", "tenant_id", "dept_id", "app_id",
        "key_id", "source", "user_id", "ip_address",
        "policy_source", "detection_mode", "latency_ms",
    ])

    # Rows
    for item in items:
        writer.writerow([
            item.trace_id,
            item.created_at.isoformat(),
            item.decision,
            item.risk_score,
            item.confidence,
            item.confidence_band,
            item.primary_reason,
            "|".join(item.threats or []),
            item.tenant_id,
            item.dept_id,
            item.app_id,
            item.key_id,
            item.source,
            item.user_id,
            item.ip_address,
            item.policy_source,
            item.detection_mode,
            item.latency_ms,
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type = "text/csv",
        headers    = {
            "Content-Disposition": "attachment; filename=wrapsec_audit_export.csv"
        },
    )