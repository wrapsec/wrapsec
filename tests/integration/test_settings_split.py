# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
tenant_settings / platform_settings and the 0017 backfill (settings split, C2a).

Requires real PostgreSQL. Scopes itself by random UUIDs / unique keys and cleans
up, since these tables are not truncated between tests.
"""
import uuid

import pytest
import sqlalchemy as sa

from db.models import PlatformSettingsModel, TenantModel, TenantSettingsModel
from db.repositories.settings import (
    PlatformSettingsRepository,
    TenantSettingsRepository,
)


async def _mk_tenant(session):
    tid = uuid.uuid4()
    session.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await session.flush()
    return tid


@pytest.mark.asyncio
async def test_tenant_settings_isolated_per_tenant(pg_db):
    """The same key holds independent values per tenant; no cross-tenant leak."""
    tid_a = await _mk_tenant(pg_db)
    tid_b = await _mk_tenant(pg_db)
    try:
        repo = TenantSettingsRepository(pg_db)
        await repo.set(tid_a, "policy_thresholds", {"block_threshold": 0.9})
        await repo.set(tid_b, "policy_thresholds", {"block_threshold": 0.5})
        await pg_db.commit()

        assert (await repo.get(tid_a, "policy_thresholds"))["block_threshold"] == 0.9
        assert (await repo.get(tid_b, "policy_thresholds"))["block_threshold"] == 0.5
        # A key set for A must not appear for B, and vice versa
        assert await repo.get(tid_a, "detection_layers") is None
    finally:
        for tid in (tid_a, tid_b):
            await pg_db.execute(sa.delete(TenantSettingsModel).where(TenantSettingsModel.tenant_id == tid))
            await pg_db.execute(sa.delete(TenantModel).where(TenantModel.id == tid))
        await pg_db.commit()


@pytest.mark.asyncio
async def test_tenant_settings_set_updates_existing(pg_db):
    tid = await _mk_tenant(pg_db)
    try:
        repo = TenantSettingsRepository(pg_db)
        await repo.set(tid, "rate_limit", {"per_minute": 60})
        await repo.set(tid, "rate_limit", {"per_minute": 120})
        await pg_db.commit()
        assert (await repo.get(tid, "rate_limit"))["per_minute"] == 120
    finally:
        await pg_db.execute(sa.delete(TenantSettingsModel).where(TenantSettingsModel.tenant_id == tid))
        await pg_db.execute(sa.delete(TenantModel).where(TenantModel.id == tid))
        await pg_db.commit()


@pytest.mark.asyncio
async def test_platform_settings_get_set(pg_db):
    key = f"ctrl-{uuid.uuid4().hex[:8]}"
    try:
        repo = PlatformSettingsRepository(pg_db)
        assert await repo.get(key) is None
        await repo.set(key, {"maintenance": True})
        await pg_db.commit()
        assert (await repo.get(key))["maintenance"] is True
    finally:
        await pg_db.execute(sa.delete(PlatformSettingsModel).where(PlatformSettingsModel.key == key))
        await pg_db.commit()


@pytest.mark.asyncio
async def test_backfill_copies_legacy_settings_to_default_tenant(pg_db):
    """0017 backfill: legacy settings rows land in tenant_settings under default."""
    # Ensure a default tenant exists (the conftest seeds one; create if missing).
    default_tid = (await pg_db.execute(
        sa.text("SELECT id FROM tenants WHERE slug = 'default' LIMIT 1")
    )).scalar()
    if default_tid is None:
        default_tid = uuid.uuid4()
        pg_db.add(TenantModel(id=default_tid, slug="default", name="Default"))
        await pg_db.flush()

    key = f"legacy-{uuid.uuid4().hex[:8]}"
    await pg_db.execute(
        sa.text("INSERT INTO settings (key, value, updated_at) VALUES (:k, :v, now())")
        .bindparams(k=key, v='{"per_minute": 42}')
    )
    # Mirrors the INSERT in 0017, scoped to this test's key.
    await pg_db.execute(
        sa.text(
            "INSERT INTO tenant_settings (tenant_id, key, value, updated_at) "
            "SELECT :tid, key, value, updated_at FROM settings WHERE key = :k "
            "ON CONFLICT (tenant_id, key) DO NOTHING"
        ).bindparams(tid=default_tid, k=key)
    )
    await pg_db.commit()
    try:
        got = await TenantSettingsRepository(pg_db).get(default_tid, key)
        assert got == {"per_minute": 42}
    finally:
        await pg_db.execute(sa.delete(TenantSettingsModel).where(TenantSettingsModel.key == key))
        await pg_db.execute(sa.text("DELETE FROM settings WHERE key = :k").bindparams(k=key))
        await pg_db.commit()
