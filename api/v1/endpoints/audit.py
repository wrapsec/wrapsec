# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import csv
import hashlib
import io
import uuid
from services.time import date_range_bounds, to_iso_z, utc_now
from typing import Literal
from fastapi import APIRouter, Query, Depends, Request
from api.v1.dependencies.auth import get_current_principal, endpoint_rate_limit
from api.v1.dependencies.scope import get_audit_scope
from domain.entities.principal import Principal
from domain.value_objects.severity import compute_severity
from fastapi.responses import JSONResponse
from sqlalchemy import func, case, Integer, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import StreamingResponse
from api.v1.dependencies.db import get_db
from db.repositories.audit import AuditRepository
from db.models import AuditLogModel, DepartmentModel, ApplicationModel, ProxyInteractionModel

router = APIRouter()


def _date_range(from_value: str | None, to_value: str | None):
    """Parse from/to query params into aware-UTC created_at bounds via the
    shared services.time helper, surfacing a parse error as a ValidationError.
    A date-only `to` covers the whole day (see date_range_bounds). Single
    boundary rule for every audit query."""
    try:
        return date_range_bounds(from_value, to_value)
    except ValueError:
        from errors.exceptions import ValidationError
        raise ValidationError(
            "Invalid date format. Use ISO 8601, e.g. 2026-01-15T00:00:00Z"
        )


def _parse_uuid_filter(value: str | None, field: str) -> str | None:
    """
    M6: audit list filters that previously accepted arbitrary substrings for
    UUID columns are now UUID-strict. Rejecting invalid UUIDs at the boundary
    closes the substring-probe user-enumeration path.
    """
    if not value:
        return None
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError):
        from errors.exceptions import ValidationError
        raise ValidationError(
            f"Invalid {field}: must be a UUID"
        )


def _format_item(
    item,
    dept_names:  dict,
    app_names:   dict,
    proxy_map:   dict,
) -> dict:
    proxy = proxy_map.get(str(item.proxy_interaction_id)) if item.proxy_interaction_id else None
    return {
        "trace_id":              item.trace_id,
        "timestamp":             to_iso_z(item.created_at),
        "tenant_id":             item.tenant_id,
        "decision":              item.decision,
        "output_decision":       proxy.output_decision if proxy else None,
        "provider":              proxy.provider        if proxy else None,
        "model":                 proxy.model           if proxy else None,
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
        "dept_name":             dept_names.get(item.dept_id),
        "app_id":                item.app_id,
        "app_name":              app_names.get(item.app_id),
        "user_id":               item.user_id,
        "source":                item.source,
        "ip_address":            item.ip_address,
        "attribution_verified":  item.attribution_verified,
        "policy_source":         item.policy_source,
        "input_length":          item.input_length or 0,
        "severity":              item.severity or compute_severity(
            decision       = item.decision,
            risk_score     = item.risk_score or 0.0,
            primary_reason = item.primary_reason,
        ),
        "session_id":            item.session_id,
        "turn_index":            item.turn_index,
        "run_id":                item.run_id,
        "input_source":          item.input_source,
        "record_hash":           item.record_hash,
        "prev_hash":             item.prev_hash,
    }


async def _enrich(
    db:    AsyncSession,
    items: list,
) -> tuple[dict, dict, dict]:
    """
    Batch-resolve dept names, app names, and proxy interaction data
    for a paginated result set. Three PK-indexed lookups on small ID sets.
    IDs come from already tenant-scoped audit rows - no cross-tenant leakage.
    """
    from sqlalchemy import cast, String

    dept_ids  = list({i.dept_id  for i in items if i.dept_id})
    app_ids   = list({i.app_id   for i in items if i.app_id})
    proxy_ids = list({str(i.proxy_interaction_id) for i in items if i.proxy_interaction_id})

    dept_names: dict[str, str] = {}
    app_names:  dict[str, str] = {}
    proxy_map:  dict           = {}

    if dept_ids:
        rows = (await db.execute(
            select(DepartmentModel.id, DepartmentModel.name).where(
                cast(DepartmentModel.id, String).in_(dept_ids)
            )
        )).fetchall()
        dept_names = {str(r.id): r.name for r in rows}

    if app_ids:
        rows = (await db.execute(
            select(ApplicationModel.id, ApplicationModel.name).where(
                cast(ApplicationModel.id, String).in_(app_ids)
            )
        )).fetchall()
        app_names = {str(r.id): r.name for r in rows}

    if proxy_ids:
        rows = (await db.execute(
            select(
                ProxyInteractionModel.id,
                ProxyInteractionModel.output_decision,
                ProxyInteractionModel.provider,
                ProxyInteractionModel.model,
            ).where(cast(ProxyInteractionModel.id, String).in_(proxy_ids))
        )).fetchall()
        proxy_map = {str(r.id): r for r in rows}

    return dept_names, app_names, proxy_map


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
    sort_by:         Literal["created_at", "risk_score", "latency_ms", "decision"] = Query("created_at"),
    sort_order:      Literal["asc", "desc"]                                        = Query("desc"),
    limit:           int        = Query(50, ge=1, le=500),
    offset:          int        = Query(0, ge=0),
    db:              AsyncSession = Depends(get_db),
    _principal:      Principal    = Depends(get_current_principal),
):
    """
    Returns a paginated, filterable list of audit log entries.
    Non-admin keys are always scoped to their own dept_id and tenant_id - any
    dept_id/tenant_id query parameters from non-admin callers are ignored.
    """
    scope     = get_audit_scope(request)
    tenant_id = scope.get("tenant_id", tenant_id)
    dept_id   = scope.get("dept_id",   dept_id)

    # M6: enforce UUID for the user_id filter (was substring ILIKE).
    user_id = _parse_uuid_filter(user_id, "user_id")

    from_dt, to_dt = _date_range(from_, to)

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
        from_dt         = from_dt,
        to_dt           = to_dt,
        sort_by         = sort_by,
        sort_order      = sort_order,
        limit           = limit,
        offset          = offset,
    )

    dept_names, app_names, proxy_map = await _enrich(db, items)

    return JSONResponse(content={
        "total": total,
        "items": [_format_item(i, dept_names, app_names, proxy_map) for i in items],
    })


@router.get("/stats")
async def get_audit_stats(
    request:   Request,
    tenant_id: str | None = Query(None),
    from_:     str | None = Query(None, alias="from"),
    to:        str | None = Query(None),
    db:        AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Returns aggregated statistics for the given time range.
    Includes: total request count, block/sanitize/allow rates, avg and p95 latency,
    top threat categories, and severity breakdown (CRITICAL/HIGH/MEDIUM/LOW).
    Non-admin keys are scoped to their own tenant_id.
    Returns zeroed stats (not 404) when no requests match the filters.
    """
    scope     = get_audit_scope(request)
    tenant_id = scope.get("tenant_id", tenant_id)
    # dept_id enforcement mirrors /logs and /attribution. Without this line
    # a non-admin (dept-scoped) caller would receive tenant-wide aggregate
    # counts covering departments they are not allowed to list -- the very
    # same cross-scope leak we already close for the per-row list endpoint.
    dept_id   = scope.get("dept_id")

    from_dt, to_dt = _date_range(from_, to)

    repo  = AuditRepository(db)
    stats = await repo.get_stats(
        tenant_id = tenant_id,
        dept_id   = dept_id,
        from_dt   = from_dt,
        to_dt     = to_dt,
    )

    # Fetch severity counts - direct query for SIEM-compatible dashboard metrics
    sev_where = []
    if tenant_id:
        sev_where.append(AuditLogModel.tenant_id == tenant_id)
    if dept_id:
        sev_where.append(AuditLogModel.dept_id == dept_id)
    if from_dt:
        sev_where.append(AuditLogModel.created_at >= from_dt)
    if to_dt:
        sev_where.append(AuditLogModel.created_at <= to_dt)

    sev_query  = select(AuditLogModel.severity, func.count().label("count")).where(*sev_where).group_by(AuditLogModel.severity)
    sev_result = await db.execute(sev_query)
    sev_rows   = sev_result.fetchall()
    stats["severities_map"] = {row[0]: row[1] for row in sev_rows if row[0]}

    total = stats["total"]
    if total == 0:
        return JSONResponse(content={
            "period_from":    from_ or to_iso_z(utc_now()),
            "period_to":      to    or to_iso_z(utc_now()),
            "total_requests": 0,
            "block_count":    0,
            "sanitize_count": 0,
            "allow_count":    0,
            "block_rate":     0.0,
            "sanitize_rate":  0.0,
            "allow_rate":     0.0,
            "avg_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
            "top_threats":    [],
        })

    # Severity breakdown - for SIEM compatibility and dashboard triage
    sev_map        = stats.get("severities_map", {})
    severity_counts = {
        "CRITICAL": sev_map.get("CRITICAL", 0),
        "HIGH":     sev_map.get("HIGH",     0),
        "MEDIUM":   sev_map.get("MEDIUM",   0),
        "LOW":      sev_map.get("LOW",      0),
    }

    return JSONResponse(content={
        "period_from":    from_ or to_iso_z(utc_now()),
        "period_to":      to    or to_iso_z(utc_now()),
        "total_requests": total,
        # Return raw counts alongside rates. Callers that need to display
        # "N blocked" must use these -- reconstructing via round(rate*total)
        # loses precision after the 4-decimal rate rounding and produces
        # off-by-one drift versus /v1/audit/logs?decision=BLOCK counts.
        "block_count":    stats["block_count"],
        "sanitize_count": stats["sanitize_count"],
        "allow_count":    stats["allow_count"],
        "block_rate":     round(stats["block_count"]    / total, 4),
        "sanitize_rate":  round(stats["sanitize_count"] / total, 4),
        "allow_rate":     round(stats["allow_count"]    / total, 4),
        "avg_latency_ms": round(stats["avg_latency_ms"], 2),
        "p95_latency_ms": round(stats["p95_latency_ms"], 2),
        "top_threats":    stats["top_threats"],
        "severity_counts": severity_counts,
    })

@router.get("/attribution")
async def get_attribution_report(
    request:    Request,
    dept_id:    str | None = Query(None),
    limit:      int        = Query(10, ge=1, le=100),
    from_:      str | None = Query(None, alias="from"),
    to:         str | None = Query(None),
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Returns attribution summary - requests grouped by key, department,
    and application. Useful for security review and capacity planning.
    Supports from/to date filtering (ISO format) for time-scoped reports.
    """
    scope   = get_audit_scope(request)
    dept_id = scope.get("dept_id", dept_id)

    base_where = []
    if scope.get("tenant_id"):
        base_where.append(AuditLogModel.tenant_id == scope["tenant_id"])
    if dept_id:
        base_where.append(AuditLogModel.dept_id == dept_id)
    from_dt, to_dt = _date_range(from_, to)
    if from_dt:
        base_where.append(AuditLogModel.created_at >= from_dt)
    if to_dt:
        base_where.append(AuditLogModel.created_at <= to_dt)

    # By API key
    key_query = select(
        AuditLogModel.key_id,
        AuditLogModel.source,
        func.count().label("total"),
        func.sum(
            case((AuditLogModel.decision == "BLOCK", 1), else_=0)
        ).label("blocked"),
        func.avg(AuditLogModel.latency_ms).label("avg_latency"),
    ).where(*base_where, AuditLogModel.key_id.isnot(None)).group_by(
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

    # By department - scoped to same dept filter as rest of attribution
    dept_query = select(
        AuditLogModel.dept_id,
        func.count().label("total"),
        func.sum(
            case((AuditLogModel.decision == "BLOCK", 1), else_=0)
        ).label("blocked"),
    ).where(*base_where, AuditLogModel.dept_id.isnot(None)).group_by(
        AuditLogModel.dept_id
    ).order_by(func.count().desc()).limit(limit)

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
    app_query = select(
        AuditLogModel.app_id,
        func.count().label("total"),
        func.sum(
            case((AuditLogModel.decision == "BLOCK", 1), else_=0)
        ).label("blocked"),
        func.avg(AuditLogModel.latency_ms).label("avg_latency"),
    ).where(*base_where, AuditLogModel.app_id.isnot(None)).group_by(
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
    reason_query = select(
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
    band_query = select(
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
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Advanced cross-department analytics with time-series trend data.
    Groups requests by time period with decision breakdowns.
    """
    scope   = get_audit_scope(request)
    dept_id = scope.get("dept_id", dept_id)

    # Build base query
    stmt = select(
        func.date_trunc(group_by, AuditLogModel.created_at).label("period"),
        AuditLogModel.decision,
        func.count().label("count"),
        func.avg(AuditLogModel.risk_score).label("avg_risk_score"),
        func.avg(AuditLogModel.latency_ms).label("avg_latency_ms"),
    )

    # Apply filters - always scoped for non-admin keys
    if scope.get("tenant_id"):
        stmt = stmt.where(AuditLogModel.tenant_id == scope["tenant_id"])
    if dept_id:
        stmt = stmt.where(AuditLogModel.dept_id == dept_id)
    from_dt, to_dt = _date_range(from_date, to_date)
    if from_dt:
        stmt = stmt.where(AuditLogModel.created_at >= from_dt)
    if to_dt:
        stmt = stmt.where(AuditLogModel.created_at <= to_dt)

    stmt   = stmt.group_by("period", AuditLogModel.decision).order_by("period")
    result = await db.execute(stmt)
    rows   = result.fetchall()

    # Aggregate into time-series
    periods: dict = {}
    for row in rows:
        period_str = to_iso_z(row.period) if row.period else "unknown"
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

@router.get("/by-source")
async def get_audit_by_source(
    request:    Request,
    from_:      str | None = Query(None, alias="from"),
    to:         str | None = Query(None),
    dept_id:    str | None = Query(None),
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Security by Source: audit aggregates grouped by input_source (trust-boundary
    provenance) plus a Top Attack Origins ranking. Per source it returns volume,
    decision mix, block rate, risk distribution, and threat-category counts.

    Read-only over data already stored on audit_logs (input_source since v1.7.0);
    groups by whatever sources exist, so a new source appears with no code change.
    Non-admin keys are scoped to their tenant/dept, mirroring /stats.
    """
    scope     = get_audit_scope(request)
    tenant_id = scope.get("tenant_id")
    dept_id   = scope.get("dept_id", dept_id)

    from_dt, to_dt = _date_range(from_, to)

    repo    = AuditRepository(db)
    sources = await repo.get_stats_by_source(
        tenant_id = tenant_id,
        dept_id   = dept_id,
        from_dt   = from_dt,
        to_dt     = to_dt,
    )

    # Top Attack Origins: sources ranked by enforced-decision volume. Only
    # sources that actually delivered attacks appear, so the widget stays crisp.
    top_attack_origins = sorted(
        [
            {"input_source": s["input_source"], "attacks": s["attacks"], "total": s["total"]}
            for s in sources if s["attacks"] > 0
        ],
        key=lambda x: x["attacks"],
        reverse=True,
    )

    return JSONResponse(content={
        "period_from":        from_ or to_iso_z(utc_now()),
        "period_to":          to    or to_iso_z(utc_now()),
        "dept_id":            dept_id,
        "sources":            sources,
        "top_attack_origins": top_attack_origins,
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
    # L1: hard cap of 10K rows per call. A single call cannot request more.
    # Callers wanting more must page through by incrementing `offset` in steps
    # of `limit`. `offset` is bounded so a caller cannot force the DB to skip
    # arbitrarily far into the result set.
    limit:           int        = Query(1000,   ge=1, le=10000),
    offset:          int        = Query(0,      ge=0, le=1_000_000),
    db:              AsyncSession = Depends(get_db),
    _principal:      Principal    = Depends(get_current_principal),
    _rl:             None         = Depends(endpoint_rate_limit("audit_export_rate_limit")),
):
    """
    Exports audit logs as a CSV file for compliance reporting.

    Row limits (L1):
      * limit  <= 10_000 rows per call (hard cap)
      * offset <= 1_000_000 rows into the result set

    Callers needing the full dataset must page: repeat the call with
    offset += limit until fewer than `limit` rows are returned.

    Non-admin keys are scoped to their own dept_id.
    Response is streamed as attachment: wrapsec_audit_export.csv.
    """
    scope     = get_audit_scope(request)
    tenant_id = scope.get("tenant_id")
    dept_id   = scope.get("dept_id", dept_id)

    from_dt, to_dt = _date_range(from_, to)
    repo = AuditRepository(db)
    _, items = await repo.list(
        tenant_id       = tenant_id,
        dept_id         = dept_id,
        app_id          = app_id,
        decision        = decision,
        primary_reason  = primary_reason,
        confidence_band = confidence_band,
        from_dt         = from_dt,
        to_dt           = to_dt,
        sort_by         = "created_at",
        sort_order      = "desc",
        limit           = limit,
        offset          = offset,
    )

    output = io.StringIO()
    writer = csv.writer(output)

    # Header - ip_address is hashed, user_id truncated (GDPR compliance)
    writer.writerow([
        "trace_id", "timestamp", "decision", "risk_score",
        "confidence", "confidence_band", "primary_reason",
        "threats", "tenant_id", "dept_id", "app_id",
        "key_id", "source", "user_id_prefix", "ip_address_hash",
        "policy_source", "detection_mode", "latency_ms",
    ])

    # Rows
    for item in items:
        ip_hash = (
            hashlib.sha256(item.ip_address.encode()).hexdigest()[:16]
            if item.ip_address else None
        )
        user_prefix = item.user_id[:8] if item.user_id else None
        writer.writerow([
            item.trace_id,
            to_iso_z(item.created_at),
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
            user_prefix,
            ip_hash,
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