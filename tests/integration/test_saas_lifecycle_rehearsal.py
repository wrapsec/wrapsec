# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
SaaS lifecycle rehearsal (refplugin increment 3): the whole baseline, composed.

One end-to-end pass proves the multi-tenant control plane and the plugin seams
work TOGETHER, not just in isolation:

  provision  -> platform operator creates a tenant + bootstraps its first admin
  entitle    -> a billing plugin writes the tenant's plan into the reserved
                plugin:<name>:<key> settings namespace (2.11)
  limit      -> a registered policy layer reads that entitlement and clamps the
                resolved policy as a final ceiling (2.9)
  suspend    -> the operator suspends the tenant; its admin is locked out (1.6)
  reactivate -> the operator restores access

Every step uses the real endpoints/seams shipped in Phase 1 + Phase 2. This is
the acceptance rehearsal that lets the baseline be declared complete.
"""
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

import services.policy_layers as pl
from config.settings import get_settings
from db.repositories.settings import TenantSettingsRepository, plugin_settings_key

# Every table with a FK to tenants (RESTRICT), cleaned by tenant_id before the
# tenant row itself. Deleting from an empty one is a harmless no-op.
_TENANT_CHILD_TABLES = (
    "webhook_delivery_attempts", "webhook_endpoints", "proxy_interactions",
    "api_keys", "applications", "departments", "admin_events",
    "email_outbox", "memberships", "tenant_settings",
)
from services.policy_layers import register_policy_layer

settings = get_settings()

_PLAN_KEY = plugin_settings_key("refplugin", "plan")   # plugin:refplugin:plan
_CAPS     = {"free": 5, "pro": 30}                       # plan -> rate_limit ceiling


def _op():
    return {"x-api-key": settings.admin_api_key}


async def _plan_ceiling(policy, ctx):
    """The billing plugin's policy layer: clamp rate_limit by the tenant's plan,
    read from the entitlement namespace. Fail-open by returning policy unchanged
    when no plan is set."""
    repo = TenantSettingsRepository(ctx.db)
    ent  = await repo.get(uuid.UUID(str(ctx.tenant_id)), _PLAN_KEY)
    tier = (ent or {}).get("tier")
    if tier not in _CAPS:
        return policy
    rl = {**policy.get("rate_limit", {}), "per_minute": min(
        policy.get("rate_limit", {}).get("per_minute", 60), _CAPS[tier])}
    return {**policy, "rate_limit": rl}


@pytest.mark.asyncio
async def test_saas_lifecycle_rehearsal(client):
    from services.policy_resolver import resolve_policy

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf     = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    before = list(pl._LAYERS)
    slug   = f"acme-{uuid.uuid4().hex[:8]}"
    email  = f"admin-{uuid.uuid4().hex[:6]}@acme-corp.com"
    tid    = None
    try:
        # -- provision: operator creates the tenant + bootstraps its first admin --
        r = await client.post("/v1/admin/tenants", json={"slug": slug, "name": "Acme"}, headers=_op())
        assert r.status_code == 201, r.text
        tid = r.json()["id"]
        assert r.json()["status"] == "active"

        rb = await client.post(
            f"/v1/admin/tenants/{tid}/bootstrap-admin",
            json={"email": email, "password": "StrongPass1!"}, headers=_op(),
        )
        assert rb.status_code == 201, rb.text

        # The provisioned admin's first login carries force_password_change (the
        # operator set a temporary password), so they are locked to the change-
        # password path until they rotate it (middleware Step 6).
        lg = await client.post("/v1/auth/login", json={"email": email, "password": "StrongPass1!"})
        assert lg.status_code == 200, lg.text
        assert lg.json()["force_password_change"] is True
        tmp_hdr = {"Authorization": f"Bearer {lg.json()['access_token']}"}
        assert (await client.get("/v1/admin/tenant", headers=tmp_hdr)).status_code == 403

        cp = await client.post(
            "/v1/auth/change-password", headers=tmp_hdr,
            json={"current_password": "StrongPass1!", "new_password": "StrongPass2!"})
        assert cp.status_code == 200, cp.text

        # Re-authenticate with the rotated password; now the admin can operate.
        lg2 = await client.post("/v1/auth/login", json={"email": email, "password": "StrongPass2!"})
        assert lg2.status_code == 200 and lg2.json()["force_password_change"] is False
        hdr = {"Authorization": f"Bearer {lg2.json()['access_token']}"}
        assert (await client.get("/v1/admin/tenant", headers=hdr)).status_code == 200

        # -- limit (baseline): with the plugin layer registered but no plan set,
        #    the ceiling is a no-op -> core default survives (fail-open) --
        register_policy_layer(_plan_ceiling)
        async with sf() as db:
            p, _ = await resolve_policy(db, tenant_id=str(tid))
        assert p["rate_limit"]["per_minute"] == 60

        # -- entitle + limit (free): the plugin writes a Free plan; the layer
        #    clamps the resolved policy to the Free ceiling --
        async with sf() as db:
            await TenantSettingsRepository(db).set(
                uuid.UUID(str(tid)), _PLAN_KEY, {"tier": "free"}, allow_plugin_namespace=True)
            await db.commit()
        async with sf() as db:
            p, _ = await resolve_policy(db, tenant_id=str(tid))
        assert p["rate_limit"]["per_minute"] == _CAPS["free"]      # 5

        # -- upgrade: the entitlement drives the ceiling; a Pro plan raises it --
        async with sf() as db:
            await TenantSettingsRepository(db).set(
                uuid.UUID(str(tid)), _PLAN_KEY, {"tier": "pro"}, allow_plugin_namespace=True)
            await db.commit()
        async with sf() as db:
            p, _ = await resolve_policy(db, tenant_id=str(tid))
        assert p["rate_limit"]["per_minute"] == _CAPS["pro"]       # 30

        # -- suspend: the operator suspends; the tenant admin is locked out --
        s = await client.post(f"/v1/admin/tenants/{tid}/suspend", headers=_op())
        assert s.status_code == 200 and s.json()["status"] == "suspended"
        blocked = await client.get("/v1/admin/tenant", headers=hdr)
        assert blocked.status_code == 403
        assert blocked.json()["error"]["code"] == "TENANT_SUSPENDED"

        # -- reactivate: access is restored --
        ra = await client.post(f"/v1/admin/tenants/{tid}/reactivate", headers=_op())
        assert ra.status_code == 200 and ra.json()["status"] == "active"
        assert (await client.get("/v1/admin/tenant", headers=hdr)).status_code == 200
    finally:
        pl._LAYERS[:] = before
        async with sf() as db:
            uid = (await db.execute(
                text("SELECT id FROM users WHERE email = :e"), {"e": email})).scalar()
            if tid is not None:
                for tbl in _TENANT_CHILD_TABLES:
                    await db.execute(text(f"DELETE FROM {tbl} WHERE tenant_id = :t"), {"t": str(tid)})
            if uid is not None:
                await db.execute(text("DELETE FROM refresh_tokens WHERE user_id = :u"), {"u": str(uid)})
                await db.execute(text("DELETE FROM users WHERE id = :u"), {"u": str(uid)})
            if tid is not None:
                await db.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": str(tid)})
            await db.commit()
        await engine.dispose()
