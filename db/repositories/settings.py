# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import json
import logging
from uuid import UUID

from sqlalchemy import select

from db.models import PlatformSettingsModel, SettingsModel, TenantSettingsModel
from db.repositories.base import BaseRepository
from services.time import utc_now

logger = logging.getLogger("wrapsec.db")


def _loads(value) -> dict | None:
    """Decode a stored JSON settings value, guarding non-strings and bad JSON."""
    if not isinstance(value, (str, bytes, bytearray)):
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        logger.error("settings: malformed JSON value error=%s", e)
        return None


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


class TenantSettingsRepository(BaseRepository):
    """Per-tenant key/value config (tenant_settings). Flush-only; callers commit."""

    async def get(self, tenant_id: UUID, key: str) -> dict | None:
        result = await self.session.execute(
            select(TenantSettingsModel).where(
                TenantSettingsModel.tenant_id == tenant_id,
                TenantSettingsModel.key       == key,
            )
        )
        record = result.scalar_one_or_none()
        return _loads(record.value) if record else None

    async def set(self, tenant_id: UUID, key: str, value: dict) -> TenantSettingsModel:
        result = await self.session.execute(
            select(TenantSettingsModel).where(
                TenantSettingsModel.tenant_id == tenant_id,
                TenantSettingsModel.key       == key,
            )
        )
        record = result.scalar_one_or_none()
        if record:
            record.value      = json.dumps(value)
            record.updated_at = utc_now()
        else:
            record = TenantSettingsModel(
                tenant_id=tenant_id, key=key, value=json.dumps(value)
            )
            self.session.add(record)
        await self.flush()
        return record


class PlatformSettingsRepository(BaseRepository):
    """Platform / control-plane key/value config (platform_settings). Flush-only."""

    async def get(self, key: str) -> dict | None:
        result = await self.session.execute(
            select(PlatformSettingsModel).where(PlatformSettingsModel.key == key)
        )
        record = result.scalar_one_or_none()
        return _loads(record.value) if record else None

    async def set(self, key: str, value: dict) -> PlatformSettingsModel:
        result = await self.session.execute(
            select(PlatformSettingsModel).where(PlatformSettingsModel.key == key)
        )
        record = result.scalar_one_or_none()
        if record:
            record.value      = json.dumps(value)
            record.updated_at = utc_now()
        else:
            record = PlatformSettingsModel(key=key, value=json.dumps(value))
            self.session.add(record)
        await self.flush()
        return record