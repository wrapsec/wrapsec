# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from datetime import datetime
from sqlalchemy import select, func, case, cast
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import AuditLogModel
from db.repositories.base import BaseRepository


class AuditRepository(BaseRepository):

    async def create(self, data: dict) -> AuditLogModel:
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

    async def get_stats(
        self,
        tenant_id: str | None = None,
        from_dt:   datetime | None = None,
        to_dt:     datetime | None = None,
    ) -> dict:
        # Build shared WHERE conditions
        filters = []
        if tenant_id:
            filters.append(AuditLogModel.tenant_id == tenant_id)
        if from_dt:
            filters.append(AuditLogModel.created_at >= from_dt)
        if to_dt:
            filters.append(AuditLogModel.created_at <= to_dt)

        # Single aggregation query for counts - avoids fetching all rows into memory
        count_q = select(
            func.count().label("total"),
            func.sum(case((AuditLogModel.decision == "BLOCK",    1), else_=0)).label("block_count"),
            func.sum(case((AuditLogModel.decision == "SANITIZE", 1), else_=0)).label("sanitize_count"),
            func.sum(case((AuditLogModel.decision == "ALLOW",    1), else_=0)).label("allow_count"),
        )
        if filters:
            count_q = count_q.where(*filters)
        counts_row = (await self.session.execute(count_q)).one()

        if not counts_row.total:
            return {
                "total":          0,
                "block_count":    0,
                "sanitize_count": 0,
                "allow_count":    0,
                "latencies":      [],
                "threats":        [],
            }

        # Fetch only latency_ms, pre-sorted - used for avg/p95 by caller
        lat_q = select(AuditLogModel.latency_ms).order_by(AuditLogModel.latency_ms)
        if filters:
            lat_q = lat_q.where(*filters)
        lat_rows  = (await self.session.execute(lat_q)).fetchall()
        latencies = [r[0] for r in lat_rows if r[0] is not None]

        # Fetch only threats column - unnest JSONB arrays in Python
        threat_q = select(AuditLogModel.threats)
        if filters:
            threat_q = threat_q.where(*filters)
        threat_rows = (await self.session.execute(threat_q)).fetchall()
        threats: list[str] = []
        for (threat_list,) in threat_rows:
            threats.extend(threat_list or [])

        return {
            "total":          counts_row.total,
            "block_count":    counts_row.block_count    or 0,
            "sanitize_count": counts_row.sanitize_count or 0,
            "allow_count":    counts_row.allow_count    or 0,
            "latencies":      latencies,
            "threats":        threats,
        }