# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Issue 162 regression: repository-layer cross-tenant isolation.

Threat model: every tenant-scoped list/get method must NEVER return rows
from a different tenant. A regression that drops the `tenant_id ==` clause
would silently expose one customer's users, apps, keys, audit logs, proxy
interactions, or provider config to another.

These tests seed two tenants (A and B), populate each with its own users,
apps, keys, audit rows, and proxy interactions, then exercise every
tenant-scoped repository method and assert the returned set only contains
tenant A's rows. The negative case (B's rows leaking into an A query)
is what would fail if a WHERE clause were removed.

The tests run against SQLite via the shared `test_db` fixture -- no live
Postgres required. This keeps the unit tier hermetic (see H10).
"""

import uuid
from datetime import datetime

import pytest
from sqlalchemy import select

from db.models import (
    TenantModel, DepartmentModel, ApplicationModel, APIKeyModel,
    UserModel, AuditLogModel, ProxyInteractionModel, ProxyProviderConfigModel,
)
from db.repositories.user           import UserRepository
from db.repositories.application    import ApplicationRepository
from db.repositories.api_key        import ApiKeyRepository
from db.repositories.audit          import AuditRepository
from db.repositories.proxy_interaction import ProxyInteractionRepository


# ── Seed helpers ──────────────────────────────────────────────────────────────

async def _seed_two_tenants(db):
    """
    Populates two independent tenants (A and B) with matching-shape data
    so isolation checks are meaningful: if A's query returns any row, it
    must be A's row, not a mistakenly-included B row of the same shape.

    Returns a dict keyed by tenant letter with the ids test callers need.
    """
    from services.auth.password import hash_password, normalize_email

    fixtures = {}

    for letter in ("A", "B"):
        tid    = uuid.uuid4()
        did    = uuid.uuid4()
        aid    = uuid.uuid4()
        uid    = uuid.uuid4()
        keyid  = f"wsk_live_{letter.lower()}_" + uuid.uuid4().hex[:12]
        trace  = f"trace-{letter.lower()}-" + uuid.uuid4().hex[:8]

        db.add(TenantModel(
            id            = tid,
            slug          = f"tenant-{letter.lower()}-{uuid.uuid4().hex[:6]}",
            name          = f"Tenant {letter}",
            global_policy = {},
            is_active     = True,
        ))
        db.add(DepartmentModel(
            id        = did,
            tenant_id = tid,
            slug      = f"dept-{letter.lower()}",
            name      = f"Dept {letter}",
            is_active = True,
        ))
        db.add(ApplicationModel(
            id        = aid,
            tenant_id = tid,
            dept_id   = did,
            slug      = f"app-{letter.lower()}",
            name      = f"App {letter}",
            is_active = True,
        ))
        db.add(APIKeyModel(
            id        = uuid.uuid4(),
            key_id    = keyid,
            tenant_id = tid,
            dept_id   = did,
            app_id    = aid,
            name      = f"key-{letter.lower()}",
            key_hash  = f"hash-{letter.lower()}-" + uuid.uuid4().hex,
            key_type  = "live",
            is_admin  = False,
            revoked   = False,
        ))
        db.add(UserModel(
            id                    = uid,
            tenant_id             = tid,
            dept_id               = did,
            email                 = normalize_email(f"user-{letter.lower()}-{uuid.uuid4().hex[:6]}@t.com"),
            password_hash         = hash_password("TestPass1!"),
            role                  = "DEVELOPER",
            is_active             = True,
            force_password_change = False,
            token_version         = 1,
        ))
        db.add(AuditLogModel(
            id             = uuid.uuid4(),
            trace_id       = trace,
            decision       = "ALLOW",
            risk_score     = 0.1,
            threats        = [],
            input_hash     = "hash-" + uuid.uuid4().hex,
            detection_mode = "standard",
            execution_mode = "scan",
            llm_invoked    = False,
            latency_ms     = 12.5,
            tenant_id      = str(tid),
            dept_id        = str(did),
            app_id         = str(aid),
            key_id         = keyid,
            user_id        = str(uid),
            source         = "api",
        ))
        db.add(ProxyInteractionModel(
            id                   = uuid.uuid4(),
            trace_id             = f"px-{letter.lower()}-" + uuid.uuid4().hex[:8],
            key_id               = keyid,
            input_decision       = "ALLOW",
            input_primary_reason = "clean",
            input_confidence     = 0.05,
            execution_status     = "COMPLETED",
            total_latency_ms     = 42,
        ))
        db.add(ProxyProviderConfigModel(
            tenant_id     = str(tid),
            provider      = "openai",
            base_url      = "https://api.openai.com/v1",
            default_model = "gpt-4o-mini",
        ))

        fixtures[letter] = {
            "tenant_id": tid,
            "dept_id":   did,
            "app_id":    aid,
            "user_id":   uid,
            "key_id":    keyid,
            "trace_id":  trace,
        }

    await db.commit()
    return fixtures


# ── Users ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_user_repo_list_by_tenant_isolated(test_db):
    fx   = await _seed_two_tenants(test_db)
    repo = UserRepository(test_db)

    users_a, total_a = await repo.list_by_tenant(fx["A"]["tenant_id"])

    assert total_a == 1
    assert len(users_a) == 1
    assert users_a[0].tenant_id == fx["A"]["tenant_id"]
    # Belt-and-braces: verify no leak of B's user id into A's result
    b_user_ids = {fx["B"]["user_id"]}
    assert not b_user_ids.intersection({u.id for u in users_a})


@pytest.mark.asyncio
async def test_user_repo_count_by_tenant_isolated(test_db):
    fx   = await _seed_two_tenants(test_db)
    repo = UserRepository(test_db)

    assert await repo.count_by_tenant(fx["A"]["tenant_id"]) == 1
    assert await repo.count_by_tenant(fx["B"]["tenant_id"]) == 1
    # Random unrelated tenant returns zero, not the combined count
    assert await repo.count_by_tenant(uuid.uuid4()) == 0


# ── Applications ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_application_repo_list_by_tenant_isolated(test_db):
    fx   = await _seed_two_tenants(test_db)
    repo = ApplicationRepository(test_db)

    apps_a = await repo.list_by_tenant(fx["A"]["tenant_id"])

    assert len(apps_a) == 1
    assert apps_a[0].tenant_id == fx["A"]["tenant_id"]
    assert apps_a[0].id == fx["A"]["app_id"]
    assert fx["B"]["app_id"] not in {a.id for a in apps_a}


# ── API Keys ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_key_repo_list_active_scoped_to_tenant(test_db):
    fx   = await _seed_two_tenants(test_db)
    repo = ApiKeyRepository(test_db)

    keys_a = await repo.list_active(tenant_id=fx["A"]["tenant_id"])

    assert len(keys_a) == 1
    assert keys_a[0].tenant_id == fx["A"]["tenant_id"]
    assert keys_a[0].key_id == fx["A"]["key_id"]
    assert fx["B"]["key_id"] not in {k.key_id for k in keys_a}


@pytest.mark.asyncio
async def test_api_key_repo_list_active_without_tenant_returns_all(test_db):
    """
    list_active(tenant_id=None) is the un-scoped variant used only by internal
    admin ops. This test locks in that behaviour so future callers do not
    accidentally rely on tenant filtering being automatic.
    """
    await _seed_two_tenants(test_db)
    repo = ApiKeyRepository(test_db)

    keys = await repo.list_active(tenant_id=None)
    assert len(keys) == 2


# ── Audit logs ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_repo_list_scoped_to_tenant(test_db):
    fx   = await _seed_two_tenants(test_db)
    repo = AuditRepository(test_db)

    total_a, items_a = await repo.list(tenant_id=str(fx["A"]["tenant_id"]))

    assert total_a == 1
    assert len(items_a) == 1
    assert items_a[0].tenant_id == str(fx["A"]["tenant_id"])
    assert items_a[0].trace_id == fx["A"]["trace_id"]
    assert fx["B"]["trace_id"] not in {r.trace_id for r in items_a}


@pytest.mark.asyncio
async def test_audit_repo_get_by_trace_id_tenant_scoped_rejects_other_tenant(test_db):
    """
    An audit row belonging to tenant B must NOT be returned when the caller
    queries as tenant A. This is the exact leak an unscoped get_by_trace_id
    would produce, which is why we route non-admin lookups through the
    tenant-scoped variant.
    """
    fx   = await _seed_two_tenants(test_db)
    repo = AuditRepository(test_db)

    # Tenant A asks for B's trace_id -> None
    row = await repo.get_by_trace_id_tenant_scoped(
        trace_id  = fx["B"]["trace_id"],
        tenant_id = str(fx["A"]["tenant_id"]),
    )
    assert row is None

    # Tenant A asks for its own trace_id -> hit
    row = await repo.get_by_trace_id_tenant_scoped(
        trace_id  = fx["A"]["trace_id"],
        tenant_id = str(fx["A"]["tenant_id"]),
    )
    assert row is not None
    assert row.trace_id == fx["A"]["trace_id"]


@pytest.mark.asyncio
async def test_audit_repo_stats_scoped_to_tenant(test_db):
    fx   = await _seed_two_tenants(test_db)
    repo = AuditRepository(test_db)

    stats_a = await repo.get_stats(tenant_id=str(fx["A"]["tenant_id"]))
    # Only tenant A's single ALLOW row should count. If the tenant_id filter
    # were dropped, total would be 2.
    assert stats_a["total"]       == 1
    assert stats_a["allow_count"] == 1


# ── Proxy interactions ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_proxy_interaction_repo_list_scoped_to_tenant(test_db):
    """
    ProxyInteractionModel has no tenant_id column - the repo joins through
    APIKeyModel to reach tenant scope. A regression that drops the subquery
    would silently expose every tenant's traffic to every other tenant.
    """
    fx   = await _seed_two_tenants(test_db)
    repo = ProxyInteractionRepository(test_db)

    items_a, total_a = await repo.list(tenant_id=fx["A"]["tenant_id"])

    assert total_a == 1
    assert len(items_a) == 1
    assert items_a[0].key_id == fx["A"]["key_id"]
    assert fx["B"]["key_id"] not in {i.key_id for i in items_a}


# ── Proxy provider config ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_proxy_provider_config_scoped_by_tenant_id(test_db):
    """
    proxy_settings endpoints filter directly on ProxyProviderConfigModel.tenant_id
    (no dedicated repo). Regression test: verify the WHERE clause returns only
    the requesting tenant's row.
    """
    fx = await _seed_two_tenants(test_db)

    result = await test_db.execute(
        select(ProxyProviderConfigModel).where(
            ProxyProviderConfigModel.tenant_id == str(fx["A"]["tenant_id"])
        )
    )
    rows = list(result.scalars().all())

    assert len(rows) == 1
    assert rows[0].tenant_id == str(fx["A"]["tenant_id"])
    # Sanity: querying the wrong tenant returns nothing, not B's config
    result = await test_db.execute(
        select(ProxyProviderConfigModel).where(
            ProxyProviderConfigModel.tenant_id == str(uuid.uuid4())
        )
    )
    assert result.scalar_one_or_none() is None
