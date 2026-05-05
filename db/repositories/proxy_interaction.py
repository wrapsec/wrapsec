# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid as _uuid
from sqlalchemy import select, func, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import APIKeyModel, ProxyInteractionModel
from db.repositories.base import BaseRepository


class ProxyInteractionRepository(BaseRepository):
    # No create() method — proxy interaction rows are written directly in the proxy
    # endpoint (_log_interaction) using db.add() for performance. Any validation
    # that would live here must be maintained in that write path instead.

    async def get_by_trace_id(self, trace_id: str) -> ProxyInteractionModel | None:
        result = await self.session.execute(
            select(ProxyInteractionModel).where(
                ProxyInteractionModel.trace_id == trace_id
            )
        )
        return result.scalar_one_or_none()

    async def list(
        self,
        tenant_id:        _uuid.UUID | None = None,
        key_id:           str | None = None,
        execution_status: str | None = None,
        limit:            int = 50,
        offset:           int = 0,
    ) -> tuple[list[ProxyInteractionModel], int]:
        query = select(ProxyInteractionModel)

        # Scope to tenant — subquery on api_keys since ProxyInteractionModel has no tenant_id
        if tenant_id is not None:
            tenant_keys = select(APIKeyModel.key_id).where(
                APIKeyModel.tenant_id == tenant_id
            )
            query = query.where(ProxyInteractionModel.key_id.in_(tenant_keys))

        if key_id:
            query = query.where(ProxyInteractionModel.key_id == key_id)

        if execution_status:
            query = query.where(ProxyInteractionModel.execution_status == execution_status)

        count_query  = select(func.count()).select_from(query.subquery())
        total_result = await self.session.execute(count_query)
        total        = total_result.scalar() or 0

        query  = query.order_by(desc(ProxyInteractionModel.created_at))
        query  = query.limit(limit).offset(offset)
        result = await self.session.execute(query)
        items  = list(result.scalars().all())

        return items, total