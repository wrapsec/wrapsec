# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import ApplicationModel
from db.repositories.base import BaseRepository


class ApplicationRepository(BaseRepository):

    async def get_by_id(self, app_id) -> ApplicationModel | None:
        result = await self.session.execute(
            select(ApplicationModel).where(
                ApplicationModel.id        == app_id,
                ApplicationModel.is_active == True,
            )
        )
        return result.scalar_one_or_none()

    async def list_by_dept(self, dept_id) -> list[ApplicationModel]:
        result = await self.session.execute(
            select(ApplicationModel).where(
                ApplicationModel.dept_id   == dept_id,
                ApplicationModel.is_active == True,
            ).order_by(ApplicationModel.created_at)
        )
        return list(result.scalars().all())

    async def list_by_tenant(self, tenant_id) -> list[ApplicationModel]:
        result = await self.session.execute(
            select(ApplicationModel).where(
                ApplicationModel.tenant_id == tenant_id,
                ApplicationModel.is_active == True,
            ).order_by(ApplicationModel.created_at)
        )
        return list(result.scalars().all())

    async def create(self, data: dict) -> ApplicationModel:
        record = ApplicationModel(**data)
        self.session.add(record)
        await self.commit()
        return record

    async def update(self, app_id, data: dict) -> ApplicationModel | None:
        record = await self.get_by_id(app_id)
        if not record:
            return None
        for key, value in data.items():
            setattr(record, key, value)
        await self.commit()
        return record