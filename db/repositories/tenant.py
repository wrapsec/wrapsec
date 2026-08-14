# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from uuid import UUID

from sqlalchemy import func, select

from db.models import TenantModel
from db.repositories.base import BaseRepository
from services.time import utc_now


class TenantRepository(BaseRepository):

    async def create(self, *, slug: str, name: str, description: str | None = None,
                     created_by: str | None = None) -> TenantModel:
        """
        Creates a tenant (status defaults to active). The single create path shared
        by the startup seed and platform-operator provisioning, so the default
        tenant is structurally identical to any provisioned one. Raises ValueError
        if the slug is already taken (any status). Flush-only; caller commits.
        """
        existing = await self.session.scalar(
            select(func.count()).select_from(TenantModel).where(TenantModel.slug == slug)
        )
        if existing:
            raise ValueError(f"A tenant with slug '{slug}' already exists.")
        tenant = TenantModel(slug=slug, name=name, description=description, created_by=created_by)
        self.session.add(tenant)
        await self.flush()
        return tenant

    async def list_all(self) -> list[TenantModel]:
        """All tenants, any status (platform-operator view). Newest first."""
        result = await self.session.execute(
            select(TenantModel).order_by(TenantModel.created_at.desc())
        )
        return list(result.scalars().all())

    async def set_status(self, tenant_id: UUID, status: str) -> TenantModel | None:
        """Suspend/reactivate a tenant. suspended_at tracks the last suspension."""
        tenant = await self.get_by_id(tenant_id)
        if tenant is None:
            return None
        tenant.status       = status
        tenant.suspended_at = utc_now() if status == "suspended" else None
        return tenant

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