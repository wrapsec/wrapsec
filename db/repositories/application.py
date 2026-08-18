# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from sqlalchemy import func, select

from db.models import ApplicationModel
from db.repositories.base import BaseRepository


class ApplicationRepository(BaseRepository):

    async def count_active_by_dept(self, tenant_id) -> dict[str, int]:
        """Active application count per department for a tenant (dept_id -> count)."""
        result = await self.session.execute(
            select(ApplicationModel.dept_id, func.count())
            .where(
                ApplicationModel.tenant_id == tenant_id,
                ApplicationModel.is_active == True,
            )
            .group_by(ApplicationModel.dept_id)
        )
        return {str(dept_id): count for dept_id, count in result.all()}

    async def get_by_slug(self, tenant_id, slug: str) -> ApplicationModel | None:
        result = await self.session.execute(
            select(ApplicationModel).where(
                ApplicationModel.tenant_id == tenant_id,
                ApplicationModel.slug      == slug,
                ApplicationModel.is_active == True,
            )
        )
        return result.scalar_one_or_none()

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
        await self.flush()
        return record

    async def update(self, app_id, data: dict) -> ApplicationModel | None:
        _UPDATABLE = frozenset({
            "name", "description", "owner_name", "owner_email", "environment",
            "metadata_", "policy_override", "rate_limit_override", "is_active",
        })
        record = await self.get_by_id(app_id)
        if not record:
            return None
        for key, value in data.items():
            if key not in _UPDATABLE:
                raise ValueError(f"Field '{key}' cannot be updated via update().")
            setattr(record, key, value)
        await self.flush()
        return record