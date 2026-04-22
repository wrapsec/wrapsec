from datetime import datetime
from sqlalchemy import select, func, text
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
        but belongs to a different department — caller treats as 404.
        Used by all non-admin key requests to prevent cross-dept leakage.
        """
        result = await self.session.execute(
            select(AuditLogModel).where(
                AuditLogModel.trace_id == trace_id,
                AuditLogModel.dept_id  == dept_id,
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
            query = query.where(AuditLogModel.user_id.ilike(f"%{user_id}%"))
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
            import json
            from sqlalchemy import text
            val = json.dumps([threat_category.upper()])
            query = query.where(
                text(f"threats::jsonb @> '{val}'::jsonb")
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
        query = select(AuditLogModel)

        if tenant_id:
            query = query.where(AuditLogModel.tenant_id == tenant_id)
        if from_dt:
            query = query.where(AuditLogModel.created_at >= from_dt)
        if to_dt:
            query = query.where(AuditLogModel.created_at <= to_dt)

        result = await self.session.execute(query)
        items  = result.scalars().all()

        if not items:
            return {
                "total":          0,
                "block_count":    0,
                "sanitize_count": 0,
                "allow_count":    0,
                "latencies":      [],
                "threats":        [],
            }

        latencies = [i.latency_ms for i in items]
        threats   = []
        for item in items:
            threats.extend(item.threats or [])

        return {
            "total":          len(items),
            "block_count":    sum(1 for i in items if i.decision == "BLOCK"),
            "sanitize_count": sum(1 for i in items if i.decision == "SANITIZE"),
            "allow_count":    sum(1 for i in items if i.decision == "ALLOW"),
            "latencies":      sorted(latencies),
            "threats":        threats,
        }