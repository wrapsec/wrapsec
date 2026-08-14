# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Per-tenant audit retention (2.1). The worker iterates tenants, resolves each
tenant's window (tenant_settings -> platform_settings -> env), and deletes only
that tenant's expired audit_logs. Un-attributed rows use the env default.
"""
import uuid
from datetime import timedelta

import pytest
import sqlalchemy as sa

from config.settings import get_settings
from db.models import (
    AuditLogModel,
    PlatformSettingsModel,
    TenantModel,
    TenantSettingsModel,
)
from db.repositories.settings import (
    PlatformSettingsRepository,
    TenantSettingsRepository,
)
from services.time import utc_now
from workers.tasks import _cleanup_audit_logs


async def _audit(session, *, tenant_id, age_days):
    trace = f"ret-{uuid.uuid4().hex[:12]}"
    session.add(AuditLogModel(
        id=uuid.uuid4(), trace_id=trace, decision="ALLOW", risk_score=0.1, threats=[],
        input_hash="h-" + uuid.uuid4().hex, detection_mode="standard", execution_mode="scan",
        llm_invoked=False, latency_ms=1.0, input_source="user_prompt",
        tenant_id=str(tenant_id) if tenant_id else None,
        created_at=utc_now() - timedelta(days=age_days),
    ))
    return trace


async def _exists(session, trace) -> bool:
    return (await session.execute(
        sa.select(AuditLogModel.id).where(AuditLogModel.trace_id == trace)
    )).scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_retention_is_per_tenant_with_platform_and_env_fallbacks(pg_db):
    env_days = get_settings().audit_retention_days
    tid_a = uuid.uuid4()   # tenant_settings retention = 5 days
    tid_b = uuid.uuid4()   # no tenant setting -> platform_settings retention = 3 days
    pg_db.add(TenantModel(id=tid_a, slug=f"ta-{tid_a.hex[:8]}", name="A"))
    pg_db.add(TenantModel(id=tid_b, slug=f"tb-{tid_b.hex[:8]}", name="B"))
    await pg_db.flush()
    await TenantSettingsRepository(pg_db).set(tid_a, "audit_retention", {"retention_days": 5})
    await PlatformSettingsRepository(pg_db).set("audit_retention", {"retention_days": 3})

    a_old = await _audit(pg_db, tenant_id=tid_a, age_days=10)   # > 5  -> deleted
    a_new = await _audit(pg_db, tenant_id=tid_a, age_days=2)    # < 5  -> kept
    b_old = await _audit(pg_db, tenant_id=tid_b, age_days=6)    # > 3  -> deleted
    b_new = await _audit(pg_db, tenant_id=tid_b, age_days=1)    # < 3  -> kept
    orphan_old = await _audit(pg_db, tenant_id=None, age_days=env_days + 5)  # deleted (env)
    orphan_new = await _audit(pg_db, tenant_id=None, age_days=0)             # kept
    await pg_db.commit()

    try:
        await _cleanup_audit_logs()  # opens its own session against the same DB

        # pg_db must see the worker's committed deletes -> use a fresh read.
        await pg_db.rollback()
        assert not await _exists(pg_db, a_old)      # A: past its 5-day window
        assert     await _exists(pg_db, a_new)      # A: within window
        assert not await _exists(pg_db, b_old)      # B: past the platform 3-day window
        assert     await _exists(pg_db, b_new)      # B: within window
        assert not await _exists(pg_db, orphan_old)  # orphan: past the env default
        assert     await _exists(pg_db, orphan_new)  # orphan: fresh
    finally:
        for tr in (a_new, b_new, orphan_new):
            await pg_db.execute(sa.delete(AuditLogModel).where(AuditLogModel.trace_id == tr))
        await pg_db.execute(sa.delete(TenantSettingsModel).where(TenantSettingsModel.tenant_id.in_([tid_a, tid_b])))
        await pg_db.execute(sa.delete(PlatformSettingsModel).where(PlatformSettingsModel.key == "audit_retention"))
        await pg_db.execute(sa.delete(TenantModel).where(TenantModel.id.in_([tid_a, tid_b])))
        await pg_db.commit()
