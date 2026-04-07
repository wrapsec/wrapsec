from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import APIKeyModel
from db.repositories.base import BaseRepository


class ApiKeyRepository(BaseRepository):

    async def create(self, data: dict) -> APIKeyModel:
        record = APIKeyModel(**data)
        self.session.add(record)
        await self.commit()
        return record

    async def get_by_key_id(self, key_id: str) -> APIKeyModel | None:
        result = await self.session.execute(
            select(APIKeyModel).where(
                APIKeyModel.key_id  == key_id,
                APIKeyModel.revoked == False,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_hash(self, key_hash: str) -> APIKeyModel | None:
        result = await self.session.execute(
            select(APIKeyModel).where(
                APIKeyModel.key_hash == key_hash,
                APIKeyModel.revoked  == False,
            )
        )
        return result.scalar_one_or_none()

    async def list_active(self) -> list[APIKeyModel]:
        result = await self.session.execute(
            select(APIKeyModel).where(APIKeyModel.revoked == False)
            .order_by(APIKeyModel.created_at.desc())
        )
        return list(result.scalars().all())

    async def revoke(self, key_id: str) -> APIKeyModel | None:
        record = await self.get_by_key_id(key_id)
        if not record:
            return None
        record.revoked = True
        await self.commit()
        return record