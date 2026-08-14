# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Tenant usage aggregate (Phase 2, 2.7). GET /v1/admin/tenant/usage totals scan/proxy
requests and blocked/sanitized decisions over audit_logs for the caller's tenant,
by day. Must count ONLY the caller's tenant -- the metering contract must not leak.
"""
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from config.settings import get_settings
from db.models import AuditLogModel
from services.time import utc_now

settings = get_settings()


def _bearer(t):
    return {"Authorization": f"Bearer {t}"}


def _row(tenant_id, *, mode, decision):
    return AuditLogModel(
        id=uuid.uuid4(), trace_id=f"u-{uuid.uuid4().hex[:12]}", decision=decision,
        risk_score=0.5, threats=[], input_hash="h-" + uuid.uuid4().hex,
        detection_mode="standard", execution_mode=mode, llm_invoked=False,
        latency_ms=1.0, input_source="user_prompt", tenant_id=str(tenant_id),
        created_at=utc_now() - timedelta(days=1),
    )


@pytest.mark.asyncio
async def test_tenant_usage_aggregates_only_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    tid_a, tid_b = a["tenant"].id, b["tenant"].id

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    added = []
    try:
        async with sf() as db:
            rows = [
                _row(tid_a, mode="scan",  decision="BLOCK"),
                _row(tid_a, mode="scan",  decision="BLOCK"),
                _row(tid_a, mode="proxy", decision="SANITIZE"),
                # Tenant B: five blocked rows that must NOT leak into A's totals.
                *[_row(tid_b, mode="scan", decision="BLOCK") for _ in range(5)],
            ]
            for r in rows:
                db.add(r)
            added = [r.id for r in rows]
            await db.commit()

        resp = await auth_client.get("/v1/admin/tenant/usage", headers=_bearer(a["admin_token"]))
        assert resp.status_code == 200
        totals = resp.json()["totals"]
        # A's own seeded rows only (the fixture's one ALLOW/scan row is not blocked).
        assert totals["blocked"] == 2       # exactly A's two -- B's five excluded
        assert totals["sanitized"] == 1
        assert totals["proxy"] == 1
        assert totals["scan"] >= 2
        assert isinstance(resp.json()["by_day"], list) and resp.json()["by_day"]
    finally:
        async with sf() as db:
            await db.execute(sa_delete(AuditLogModel).where(AuditLogModel.id.in_(added)))
            await db.commit()
        await engine.dispose()


@pytest.mark.asyncio
async def test_tenant_usage_rejects_bad_dates(auth_client, two_tenant_setup):
    a = two_tenant_setup["A"]
    r = await auth_client.get(
        "/v1/admin/tenant/usage?from=not-a-date", headers=_bearer(a["admin_token"])
    )
    assert r.status_code == 400
