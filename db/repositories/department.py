# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import DepartmentModel
from db.repositories.base import BaseRepository


class DepartmentRepository(BaseRepository):

    async def get_default(self, tenant_id) -> DepartmentModel | None:
        result = await self.session.execute(
            select(DepartmentModel).where(
                DepartmentModel.tenant_id == tenant_id,
                DepartmentModel.slug      == "default",
                DepartmentModel.is_active == True,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, dept_id) -> DepartmentModel | None:
        result = await self.session.execute(
            select(DepartmentModel).where(
                DepartmentModel.id        == dept_id,
                DepartmentModel.is_active == True,
            )
        )
        return result.scalar_one_or_none()

    async def list_by_tenant(self, tenant_id) -> list[DepartmentModel]:
        result = await self.session.execute(
            select(DepartmentModel).where(
                DepartmentModel.tenant_id == tenant_id,
                DepartmentModel.is_active == True,
            ).order_by(DepartmentModel.created_at)
        )
        return list(result.scalars().all())

    async def create(self, data: dict) -> DepartmentModel:
        record = DepartmentModel(**data)
        self.session.add(record)
        await self.flush()
        return record

    async def update(self, dept_id, data: dict) -> DepartmentModel | None:
        _UPDATABLE = frozenset({
            "name", "description", "policy_override", "contact_email", "is_active",
        })
        record = await self.get_by_id(dept_id)
        if not record:
            return None
        for key, value in data.items():
            if key not in _UPDATABLE:
                raise ValueError(f"Field '{key}' cannot be updated via update().")
            setattr(record, key, value)
        await self.flush()
        return record