# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from uuid import UUID

from sqlalchemy import select

from db.models import TenantModel
from db.repositories.base import BaseRepository


class TenantRepository(BaseRepository):

    async def get_default(self) -> TenantModel | None:
        result = await self.session.execute(
            select(TenantModel).where(
                TenantModel.slug   == "default",
                TenantModel.status == "active",
            )
        )
        return result.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> TenantModel | None:
        result = await self.session.execute(
            select(TenantModel).where(
                TenantModel.slug   == slug,
                TenantModel.status == "active",
            )
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, tenant_id: UUID) -> TenantModel | None:
        # No status filter: suspend enforcement needs to read a suspended tenant's
        # status. Suspended tenants are rejected explicitly at the auth layer, not
        # by making their rows invisible here.
        result = await self.session.execute(
            select(TenantModel).where(TenantModel.id == tenant_id)
        )
        return result.scalar_one_or_none()