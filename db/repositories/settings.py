# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import json
from services.time import utc_now
import logging
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import SettingsModel
from db.repositories.base import BaseRepository

logger = logging.getLogger("wrapsec.db")


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
        try:
            return json.loads(record.value)
        except json.JSONDecodeError as e:
            logger.error("SettingsRepository.get: malformed JSON for key=%s error=%s", key, e)
            return None

    async def set(self, key: str, value: dict) -> SettingsModel:
        result = await self.session.execute(
            select(SettingsModel).where(SettingsModel.key == key)
        )
        record = result.scalar_one_or_none()

        if record:
            record.value      = json.dumps(value)
            record.updated_at = utc_now()
        else:
            record = SettingsModel(
                key   = key,
                value = json.dumps(value),
            )
            self.session.add(record)

        await self.flush()
        return record