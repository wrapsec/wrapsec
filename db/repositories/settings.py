import json
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import SettingsModel
from db.repositories.base import BaseRepository


class SettingsRepository(BaseRepository):

    async def get(self, key: str) -> dict | None:
        result = await self.session.execute(
            select(SettingsModel).where(SettingsModel.key == key)
        )
        record = result.scalar_one_or_none()
        if not record:
            return None
        # Guard against non-string values (e.g. MagicMock in tests)
        if not isinstance(record.value, (str, bytes, bytearray)):
            return None
        return json.loads(record.value)

    async def set(self, key: str, value: dict) -> SettingsModel:
        result = await self.session.execute(
            select(SettingsModel).where(SettingsModel.key == key)
        )
        record = result.scalar_one_or_none()

        if record:
            record.value      = json.dumps(value)
            record.updated_at = datetime.utcnow()
        else:
            record = SettingsModel(
                key   = key,
                value = json.dumps(value),
            )
            self.session.add(record)

        await self.commit()
        return record