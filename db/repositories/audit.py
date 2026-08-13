# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from __future__ import annotations

from datetime import datetime

from sqlalchemy import case, cast, func, select, text
from sqlalchemy.dialects.postgresql import JSONB

from db.models import AuditLogModel
from db.repositories.base import BaseRepository
from security.audit_chain import compute_record_hash
from services.time import ensure_utc, utc_now


class AuditRepository(BaseRepository):

    async def create(self, data: dict) -> AuditLogModel:
        # Populate created_at up front so the hash covers exactly the value
        # that lands on disk. Falling back to SQLAlchemy's default would let
        # the DB or the ORM pick a different timestamp than the one we hashed.
        data.setdefault("created_at", utc_now())

        tenant_id = data.get("tenant_id")
        if tenant_id:
            # Serialise chain reads+writes within a tenant so two concurrent
            # inserts cannot both compute prev_hash off the same row and fork
            # the chain. pg_advisory_xact_lock releases on commit/rollback,
            # which lines up exactly with the commit() below. SQLite tests are
            # single-writer per database so the lock is skipped there.
            if self.session.bind.dialect.name == "postgresql":
                await self.session.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:tid))"),
                    {"tid": tenant_id},
                )

            # `record_hash IS NOT NULL` skips any pre-v1.2.0 rows still in
            # the table -- the chain starts fresh for each tenant on the
            # first v1.2.0 write. Retroactive hashing of legacy rows is
            # deliberately out of scope.
            prev_hash = await self.session.scalar(
                select(AuditLogModel.record_hash)
                .where(
                    AuditLogModel.tenant_id   == tenant_id,
                    AuditLogModel.record_hash.is_not(None),
                )
                .order_by(AuditLogModel.created_at.desc())
                .limit(1)
            )
            data["prev_hash"]   = prev_hash
            data["record_hash"] = compute_record_hash(data, prev_hash)
        # Rows without tenant_id stay unchained (both hash cols NULL);
        # see security/audit_chain.py docstring for the rationale.

        record = AuditLogModel(**data)
        self.session.add(record)
        await self.commit()
        return record

    async def get_by_trace_id(self, trace_id: str) -> AuditLogModel | None:
        result = await self.session.execute(
            select(AuditLogModel).where(AuditLogModel.trace_id == trace_id)
        )
        return result.scalar_one_or_none()

    async def get_by_trace_id_scoped(
        self,
        trace_id: str,
        dept_id:  str,
    ) -> AuditLogModel | None:
        """
        Dept-scoped trace_id lookup. Returns None if the record exists
        but belongs to a different department - caller treats as 404.
        Used by all non-admin key requests to prevent cross-dept leakage.
        """
        result = await self.session.execute(
            select(AuditLogModel).where(
                AuditLogModel.trace_id == trace_id,
                AuditLogModel.dept_id  == dept_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_trace_id_tenant_scoped(
        self,
        trace_id:  str,
        tenant_id: str,
    ) -> AuditLogModel | None:
        """
        Tenant-scoped trace_id lookup. Used for non-admin keys with no dept_id
        (tenant-level keys). Prevents cross-tenant leakage without requiring
        a dept_id scope.
        """
        result = await self.session.execute(
            select(AuditLogModel).where(
                AuditLogModel.trace_id  == trace_id,
                AuditLogModel.tenant_id == tenant_id,
            )
        )
        return result.scalar_one_or_none()

    async def list(
        self,
        tenant_id:       str | None = None,
        execution_mode:  str | None = None,
        dept_id:         str | None = None,
        app_id:          str | None = None,
        key_id:          str | None = None,
        user_id:         str | None = None,
        source:          str | None = None,
        trace_id:        str | None = None,
        decision:        str | None = None,
        threat_category: str | None = None,
        primary_reason:  str | None = None,
        confidence_band: str | None = None,
        from_dt:         datetime | None = None,
        to_dt:           datetime | None = None,
        sort_by:         str = "created_at",
        sort_order:      str = "desc",
        limit:           int = 50,
        offset:          int = 0,
    ) -> tuple[int, list[AuditLogModel]]:
        query = select(AuditLogModel)

        if tenant_id:
            query = query.where(AuditLogModel.tenant_id == tenant_id)
        if dept_id:
            query = query.where(AuditLogModel.dept_id == dept_id)
        if app_id:
            query = query.where(AuditLogModel.app_id == app_id)
        if key_id:
            query = query.where(AuditLogModel.key_id == key_id)
        if user_id:
            # M6: previously used ILIKE substring, which allowed audit-read
            # principals to enumerate other users by probing UUID substrings.
            # user_id at this layer must be a full UUID string; equality only.
            query = query.where(AuditLogModel.user_id == user_id)
        if source:
            query = query.where(AuditLogModel.source.ilike(f"%{source}%"))
        if primary_reason:
            query = query.where(AuditLogModel.primary_reason == primary_reason)
        if confidence_band:
            query = query.where(AuditLogModel.confidence_band == confidence_band)
        if trace_id:
            query = query.where(AuditLogModel.trace_id.ilike(f"%{trace_id}%"))
        if decision:
            query = query.where(AuditLogModel.decision == decision.upper())
        if threat_category:
            query = query.where(
                cast(AuditLogModel.threats, JSONB).contains([threat_category.upper()])
            )
        if from_dt:
            query = query.where(AuditLogModel.created_at >= from_dt)
        if to_dt:
            query = query.where(AuditLogModel.created_at <= to_dt)
        if execution_mode:
            query = query.where(AuditLogModel.execution_mode == execution_mode)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total       = await self.session.scalar(count_query)

        # Sort
        SORTABLE = {
            "created_at": AuditLogModel.created_at,
            "risk_score":  AuditLogModel.risk_score,
            "latency_ms":  AuditLogModel.latency_ms,
            "decision":    AuditLogModel.decision,
        }
        sort_col = SORTABLE.get(sort_by, AuditLogModel.created_at)
        if sort_order == "asc":
            query = query.order_by(sort_col.asc())
        else:
            query = query.order_by(sort_col.desc())

        # Paginate
        query  = query.offset(offset).limit(limit)
        result = await self.session.execute(query)
        items  = result.scalars().all()

        return total or 0, list(items)

    async def list_run(
        self,
        run_id:     str | None = None,
        session_id: str | None = None,
        tenant_id:  str | None = None,
        dept_id:    str | None = None,
        limit:      int = 500,
    ) -> list[AuditLogModel]:
        """Every scan in one agent run (run_id) or conversation (session_id),
        ordered as a timeline: turn_index (NULLs last on PostgreSQL), then
        created_at. Scoped to tenant/dept so a run_id from another tenant returns
        an empty list, never another tenant's rows. Uses the ix_audit_run_created
        / ix_audit_session_created indexes."""
        if not run_id and not session_id:
            return []

        query = select(AuditLogModel)
        if run_id:
            query = query.where(AuditLogModel.run_id == run_id)
        if session_id:
            query = query.where(AuditLogModel.session_id == session_id)
        if tenant_id:
            query = query.where(AuditLogModel.tenant_id == tenant_id)
        if dept_id:
            query = query.where(AuditLogModel.dept_id == dept_id)

        query = query.order_by(
            AuditLogModel.turn_index.asc(),
            AuditLogModel.created_at.asc(),
        ).limit(limit)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_stats(
        self,
        tenant_id:       str | None = None,
        dept_id:         str | None = None,
        from_dt:         datetime | None = None,
        to_dt:           datetime | None = None,
        decision:        str | None = None,
        threat_category: str | None = None,
        execution_mode:  str | None = None,
        trace_id:        str | None = None,
    ) -> dict:
        # Aggregation is done in SQL on PostgreSQL so we do not fan out every
        # latency and threats row into a Python list -- that pattern OOMs once
        # a tenant crosses a few million audit rows. SQLite lacks percentile
        # and JSON-unnest functions, so tests fall through to a Python pass;
        # SQLite is never used in production, only for the in-memory unit-test
        # database.
        #
        # dept_id is required for non-admin callers: without it, a dept-scoped
        # user would receive tenant-wide aggregates that leak block/latency/
        # threat counts across the departments they cannot list. The endpoint
        # (api/v1/endpoints/audit.py::get_audit_stats) sources it from the
        # request scope, mirroring the dept enforcement already applied to
        # /v1/audit/logs and /v1/audit/attribution.
        filters = []
        if tenant_id:
            filters.append(AuditLogModel.tenant_id == tenant_id)
        if dept_id:
            filters.append(AuditLogModel.dept_id == dept_id)
        # audit_logs.created_at is TIMESTAMPTZ; ensure_utc normalizes the bounds
        # to aware UTC so the comparison binds aware-to-aware regardless of what
        # the caller passed.
        if from_dt:
            filters.append(AuditLogModel.created_at >= ensure_utc(from_dt))
        if to_dt:
            filters.append(AuditLogModel.created_at <= ensure_utc(to_dt))
        # The list-view filters (decision/threat/execution/trace) so a filter-scoped
        # "Security Overview" strip matches the rows the table shows exactly.
        # Mirror the same predicates used by list() to avoid strip-vs-table drift.
        if decision:
            filters.append(AuditLogModel.decision == decision.upper())
        if threat_category:
            filters.append(cast(AuditLogModel.threats, JSONB).contains([threat_category.upper()]))
        if execution_mode:
            filters.append(AuditLogModel.execution_mode == execution_mode)
        if trace_id:
            filters.append(AuditLogModel.trace_id.ilike(f"%{trace_id}%"))

        is_pg = self.session.bind.dialect.name == "postgresql"

        agg_cols = [
            func.count().label("total"),
            func.sum(case((AuditLogModel.decision == "BLOCK",    1), else_=0)).label("block_count"),
            func.sum(case((AuditLogModel.decision == "SANITIZE", 1), else_=0)).label("sanitize_count"),
            func.sum(case((AuditLogModel.decision == "ALLOW",    1), else_=0)).label("allow_count"),
            func.avg(AuditLogModel.latency_ms).label("avg_latency"),
            func.avg(AuditLogModel.risk_score).label("avg_risk"),
        ]
        if is_pg:
            # percentile_cont interpolates -- same definition Grafana, Datadog,
            # and Prometheus histogram_quantile use for SLO reporting.
            agg_cols.append(
                func.percentile_cont(0.95)
                    .within_group(AuditLogModel.latency_ms.asc())
                    .label("p95_latency")
            )

        agg_q = select(*agg_cols)
        if filters:
            agg_q = agg_q.where(*filters)
        row = (await self.session.execute(agg_q)).one()

        total = row.total or 0
        if not total:
            return {
                "total":          0,
                "block_count":    0,
                "sanitize_count": 0,
                "allow_count":    0,
                "avg_latency_ms": 0.0,
                "p95_latency_ms": 0.0,
                "avg_risk":       0.0,
                "severities_map": {},
                "top_threats":    [],
            }

        avg_latency = float(row.avg_latency or 0)
        avg_risk    = float(row.avg_risk or 0)

        # Severity distribution over the SAME filtered set (drives the strip's
        # severity mini-bar). Kept in the repo so every stats filter applies
        # uniformly rather than being re-derived at the endpoint.
        sev_q = select(AuditLogModel.severity, func.count().label("cnt"))
        if filters:
            sev_q = sev_q.where(*filters)
        sev_q = sev_q.group_by(AuditLogModel.severity)
        severities_map = {
            r.severity: r.cnt
            for r in (await self.session.execute(sev_q)).fetchall()
            if r.severity
        }

        if is_pg:
            p95_latency = float(row.p95_latency or 0)
        else:
            lat_q = select(AuditLogModel.latency_ms).order_by(AuditLogModel.latency_ms)
            if filters:
                lat_q = lat_q.where(*filters)
            lats = [
                r[0] for r in (await self.session.execute(lat_q)).fetchall()
                if r[0] is not None
            ]
            p95_latency = float(lats[int(len(lats) * 0.95)]) if lats else 0.0

        if is_pg:
            # jsonb_array_elements_text unnests each threats array into one row
            # per element; GROUP BY then collapses across all rows for category
            # counts. The physical column is JSONB (the SQLAlchemy `JSON` type
            # gets promoted to JSONB on PostgreSQL), so use the jsonb_* variant.
            threat_where = list(filters) + [AuditLogModel.threats.isnot(None)]
            threat_elem  = func.jsonb_array_elements_text(AuditLogModel.threats).label("threat")
            inner = select(threat_elem).where(*threat_where).subquery()
            top_q = (
                select(inner.c.threat, func.count().label("cnt"))
                .group_by(inner.c.threat)
                .order_by(func.count().desc())
            )
            top_threats = [
                {"category": r.threat, "count": r.cnt}
                for r in (await self.session.execute(top_q)).fetchall()
            ]
        else:
            threat_q = select(AuditLogModel.threats)
            if filters:
                threat_q = threat_q.where(*filters)
            counts: dict[str, int] = {}
            for (arr,) in (await self.session.execute(threat_q)).fetchall():
                for t in (arr or []):
                    counts[t] = counts.get(t, 0) + 1
            top_threats = sorted(
                [{"category": k, "count": v} for k, v in counts.items()],
                key=lambda x: x["count"],
                reverse=True,
            )

        return {
            "total":          total,
            "block_count":    row.block_count    or 0,
            "sanitize_count": row.sanitize_count or 0,
            "allow_count":    row.allow_count    or 0,
            "avg_latency_ms": avg_latency,
            "p95_latency_ms": p95_latency,
            "avg_risk":       avg_risk,
            "severities_map": severities_map,
            "top_threats":    top_threats,
        }

    async def get_stats_by_source(
        self,
        tenant_id:      str | None = None,
        dept_id:        str | None = None,
        from_dt:        datetime | None = None,
        to_dt:          datetime | None = None,
        high_risk_floor: float = 0.7,
    ) -> list[dict]:
        """
        Aggregate audit rows grouped by input_source (trust-boundary provenance).

        Per source: volume, decision mix, average/peak risk, high-risk count, and
        threat-category counts. Powers the Security by Source dashboard and the
        Top Attack Origins widget. Same scope/date filters and same PG-SQL /
        SQLite-Python split as get_stats; NULL input_source (pre-v1.7.0 rows) is
        folded into "user_prompt", the documented default.
        """
        filters = []
        if tenant_id:
            filters.append(AuditLogModel.tenant_id == tenant_id)
        if dept_id:
            filters.append(AuditLogModel.dept_id == dept_id)
        if from_dt:
            filters.append(AuditLogModel.created_at >= ensure_utc(from_dt))
        if to_dt:
            filters.append(AuditLogModel.created_at <= ensure_utc(to_dt))

        is_pg  = self.session.bind.dialect.name == "postgresql"
        source = func.coalesce(AuditLogModel.input_source, "user_prompt").label("input_source")

        agg_q = select(
            source,
            func.count().label("total"),
            func.sum(case((AuditLogModel.decision == "BLOCK",    1), else_=0)).label("block_count"),
            func.sum(case((AuditLogModel.decision == "SANITIZE", 1), else_=0)).label("sanitize_count"),
            func.sum(case((AuditLogModel.decision == "ALLOW",    1), else_=0)).label("allow_count"),
            func.avg(AuditLogModel.risk_score).label("avg_risk"),
            func.max(AuditLogModel.risk_score).label("max_risk"),
            func.sum(case((AuditLogModel.risk_score >= high_risk_floor, 1), else_=0)).label("high_risk_count"),
        )
        if filters:
            agg_q = agg_q.where(*filters)
        agg_q = agg_q.group_by(source)

        sources: dict[str, dict] = {}
        for r in (await self.session.execute(agg_q)).fetchall():
            key = r.input_source or "user_prompt"
            sources[key] = {
                "input_source":    key,
                "total":           r.total or 0,
                "blocked":         r.block_count    or 0,
                "sanitized":       r.sanitize_count or 0,
                "allowed":         r.allow_count    or 0,
                "avg_risk":        round(float(r.avg_risk or 0), 4),
                "max_risk":        round(float(r.max_risk or 0), 4),
                "high_risk_count": r.high_risk_count or 0,
                "threats":         {},
            }

        # Threat-category counts per source. jsonb_array_elements_text unnests the
        # threats array on PostgreSQL; SQLite falls through to a Python pass.
        if is_pg:
            threat_where = list(filters) + [AuditLogModel.threats.isnot(None)]
            threat_elem  = func.jsonb_array_elements_text(AuditLogModel.threats).label("threat")
            inner = select(source, threat_elem).where(*threat_where).subquery()
            tq = (
                select(inner.c.input_source, inner.c.threat, func.count().label("cnt"))
                .group_by(inner.c.input_source, inner.c.threat)
            )
            for r in (await self.session.execute(tq)).fetchall():
                key = r.input_source or "user_prompt"
                if key in sources:
                    sources[key]["threats"][r.threat] = r.cnt
        else:
            tq = select(source, AuditLogModel.threats)
            if filters:
                tq = tq.where(*filters)
            for r in (await self.session.execute(tq)).fetchall():
                key = r.input_source or "user_prompt"
                bucket = sources.get(key, {}).get("threats")
                if bucket is None:
                    continue
                for t in (r.threats or []):
                    bucket[t] = bucket.get(t, 0) + 1

        # Attack volume = enforced decisions (BLOCK + SANITIZE) -- the rows the
        # gateway acted on. Precise, per-row, no double counting; it drives the
        # Top Attack Origins ranking, while the threats map above breaks those
        # attacks down by category for the Security by Source panels.
        result = []
        for s in sources.values():
            s["attacks"]    = s["blocked"] + s["sanitized"]
            s["block_rate"] = round(s["blocked"] / s["total"], 4) if s["total"] else 0.0
            result.append(s)

        # Highest-volume sources first for a stable, scannable ordering.
        result.sort(key=lambda x: x["total"], reverse=True)
        return result