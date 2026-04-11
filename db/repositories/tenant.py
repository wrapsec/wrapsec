from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import TenantModel
from db.repositories.base import BaseRepository


class TenantRepository(BaseRepository):

    async def get_default(self) -> TenantModel | None:
        result = await self.session.execute(
            select(TenantModel).where(
                TenantModel.slug      == "default",
                TenantModel.is_active == True,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> TenantModel | None:
        result = await self.session.execute(
            select(TenantModel).where(
                TenantModel.slug      == slug,
                TenantModel.is_active == True,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, tenant_id) -> TenantModel | None:
        result = await self.session.execute(
            select(TenantModel).where(TenantModel.id == tenant_id)
        )
        return result.scalar_one_or_none()