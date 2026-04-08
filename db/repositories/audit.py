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

    async def list(
        self,
        tenant_id:       str | None = None,
        decision:        str | None = None,
        threat_category: str | None = None,
        from_dt:         datetime | None = None,
        to_dt:           datetime | None = None,
        limit:           int = 50,
        offset:          int = 0,
    ) -> tuple[int, list[AuditLogModel]]:
        query = select(AuditLogModel)

        if tenant_id:
            query = query.where(AuditLogModel.tenant_id == tenant_id)
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

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total       = await self.session.scalar(count_query)

        # Paginate
        query  = query.order_by(AuditLogModel.created_at.desc())
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