# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import json
import logging
from uuid import UUID

from sqlalchemy import select

from db.models import PlatformSettingsModel, TenantSettingsModel
from db.repositories.base import BaseRepository
from services.time import utc_now

logger = logging.getLogger("wrapsec.db")

# ── Plugin settings/entitlement namespace (Phase 2, 2.11 / open-core P4) ──────
# Plugin-owned config and per-tenant entitlements live in the SAME settings
# tables as core config, under a reserved key prefix. The 1.3 settings substrate
# is thereby also the "which tenant bought what" store -- no separate entitlement
# table in core. The prefix is reserved for plugin-internal writes: the core
# settings write path refuses it (allow_plugin_namespace defaults to False), so a
# tenant admin driving a core settings endpoint can never read or write a plugin
# key, and core config can never collide with the plugin namespace. A plugin
# writes its own keys by passing allow_plugin_namespace=True explicitly.
PLUGIN_KEY_PREFIX = "plugin:"


def is_plugin_settings_key(key: str) -> bool:
    """True if `key` is in the reserved plugin namespace (plugin:<name>:<key>)."""
    return isinstance(key, str) and key.startswith(PLUGIN_KEY_PREFIX)


def plugin_settings_key(plugin_name: str, key: str) -> str:
    """
    Build a namespaced settings key for a plugin: 'plugin:<name>:<key>'. The
    plugin name must be non-empty and contain no ':' so the three-part structure
    stays parseable; the key must be non-empty. This is the ONLY sanctioned way
    for a plugin to name a settings/entitlement row.
    """
    if not plugin_name or ":" in plugin_name:
        raise ValueError("plugin name must be non-empty and contain no ':'")
    if not key:
        raise ValueError("plugin settings key must be non-empty")
    return f"{PLUGIN_KEY_PREFIX}{plugin_name}:{key}"


def _guard_namespace(key: str, allow_plugin_namespace: bool) -> None:
    """Refuse a write to the reserved plugin namespace from the core path."""
    if not allow_plugin_namespace and is_plugin_settings_key(key):
        raise ValueError(
            f"settings key '{key}' is in the reserved plugin namespace "
            f"('{PLUGIN_KEY_PREFIX}...'); only a plugin may write it "
            "(pass allow_plugin_namespace=True)."
        )


def _loads(value) -> dict | None:
    """Decode a stored JSON settings value, guarding non-strings and bad JSON."""
    if not isinstance(value, (str, bytes, bytearray)):
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        logger.error("settings: malformed JSON value error=%s", e)
        return None


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

    async def set(
        self,
        tenant_id: UUID,
        key: str,
        value: dict,
        *,
        allow_plugin_namespace: bool = False,
    ) -> TenantSettingsModel:
        _guard_namespace(key, allow_plugin_namespace)
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

    async def set(
        self,
        key: str,
        value: dict,
        *,
        allow_plugin_namespace: bool = False,
    ) -> PlatformSettingsModel:
        _guard_namespace(key, allow_plugin_namespace)
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