# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Service-integration tests for services.policy_resolver.resolve_policy against a
real database.

The pure helpers (deep_merge, system_defaults, determine_policy_source) are unit
tested in tests/unit/services/test_policy_resolver.py. These exercise the async
cascade that needs real repositories: global DB settings, department and
application policy_override merging, the app/tenant mismatch guard, the
rate_limit_override column, api_key_enc decryption, and the final threshold
sanity check.
"""

import uuid

import pytest

from config.settings import get_settings
from db.models import ApplicationModel, DepartmentModel, TenantModel
from db.repositories.settings import TenantSettingsRepository
from errors.exceptions import PolicyResolutionDegraded
from security.encryption import encrypt
from services.policy_resolver import resolve_policy, resolve_policy_for_preview

pytestmark = pytest.mark.pg


async def _tenant(db):
    tid = uuid.uuid4()
    db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await db.commit()
    return tid


async def _dept(db, tenant_id, *, policy_override=None):
    did = uuid.uuid4()
    db.add(DepartmentModel(id=did, tenant_id=tenant_id, slug=f"d-{did.hex[:6]}",
                           name="D", is_active=True, policy_override=policy_override))
    await db.commit()
    return did


async def _app(db, tenant_id, dept_id, *, policy_override=None, rate_limit_override=None):
    aid = uuid.uuid4()
    db.add(ApplicationModel(
        id=aid, tenant_id=tenant_id, dept_id=dept_id, slug=f"a-{aid.hex[:6]}",
        name="A", is_active=True,
        policy_override=policy_override, rate_limit_override=rate_limit_override,
    ))
    await db.commit()
    return aid


@pytest.mark.asyncio
async def test_global_db_settings_override_system_defaults(pg_db):
    tid  = await _tenant(pg_db)
    repo = TenantSettingsRepository(pg_db)
    await repo.set(tid, "policy_thresholds", {"block_threshold": 0.8, "sanitize_threshold": 0.3})
    await repo.set(tid, "detection_layers", {"rule_enabled": False, "ml_enabled": True, "llm_enabled": False})
    await repo.set(tid, "llm_settings", {"provider": "openai", "model": "gpt-4o", "llm_trigger": 0.15})
    await repo.set(tid, "rate_limit", {"per_minute": 120})
    await pg_db.commit()

    policy, source = await resolve_policy(pg_db, tenant_id=str(tid))

    assert policy["thresholds"]["block"] == 0.8
    assert policy["thresholds"]["sanitize"] == 0.3
    # thresholds propagate to the PII guardrail
    assert policy["guardrails"]["pii"]["block_threshold"] == 0.8
    assert policy["detection"]["rule_enabled"] is False
    assert policy["detection"]["llm_enabled"] is False
    assert policy["detection"]["llm_trigger"] == 0.15
    assert policy["llm"]["model"] == "gpt-4o"
    assert policy["rate_limit"]["per_minute"] == 120
    assert source == "system_default"  # no dept/app override applied


@pytest.mark.asyncio
async def test_department_override_merges_and_sets_source(pg_db):
    tid = await _tenant(pg_db)
    did = await _dept(pg_db, tid, policy_override={"detection": {"rule_enabled": False}})

    policy, source = await resolve_policy(pg_db, tenant_id=str(tid), dept_id=str(did))

    assert policy["detection"]["rule_enabled"] is False  # overridden
    assert policy["detection"]["ml_enabled"] is True     # inherited (partial merge)
    assert source == "department_override"


@pytest.mark.asyncio
async def test_application_override_wins_and_sets_source(pg_db):
    tid = await _tenant(pg_db)
    did = await _dept(pg_db, tid, policy_override={"thresholds": {"block": 0.6}})
    aid = await _app(pg_db, tid, did, policy_override={"thresholds": {"block": 0.9}})

    policy, source = await resolve_policy(
        pg_db, tenant_id=str(tid), dept_id=str(did), app_id=str(aid)
    )

    assert policy["thresholds"]["block"] == 0.9   # app override wins over dept
    assert source == "application_override"


@pytest.mark.asyncio
async def test_application_tenant_mismatch_is_skipped(pg_db):
    tid = await _tenant(pg_db)
    did = await _dept(pg_db, tid)
    aid = await _app(pg_db, tid, did, policy_override={"thresholds": {"block": 0.95}})

    # A request whose tenant_id does not match the application's tenant must not
    # pick up that application's override (cross-tenant policy leak guard).
    other_tenant = str(uuid.uuid4())
    policy, source = await resolve_policy(
        pg_db, tenant_id=other_tenant, dept_id=str(did), app_id=str(aid)
    )

    assert policy["thresholds"]["block"] != 0.95
    assert source != "application_override"


@pytest.mark.asyncio
async def test_application_rate_limit_override_column(pg_db):
    tid = await _tenant(pg_db)
    did = await _dept(pg_db, tid)
    aid = await _app(pg_db, tid, did, rate_limit_override=250)

    policy, _ = await resolve_policy(pg_db, tenant_id=str(tid), app_id=str(aid))

    assert policy["rate_limit"]["per_minute"] == 250


@pytest.mark.asyncio
async def test_api_key_enc_decrypted_from_override(pg_db):
    secret = get_settings().secret_key
    enc    = encrypt("sk-provider-secret", secret)
    tid = await _tenant(pg_db)
    did = await _dept(pg_db, tid, policy_override={"llm": {"api_key_enc": enc}})

    policy, _ = await resolve_policy(pg_db, tenant_id=str(tid), dept_id=str(did))

    assert policy["llm"]["api_key"] == "sk-provider-secret"
    assert "api_key_enc" not in policy["llm"]   # ciphertext never leaks to callers


@pytest.mark.asyncio
async def test_api_key_enc_decryption_failure_raises(pg_db):
    tid = await _tenant(pg_db)
    did = await _dept(pg_db, tid, policy_override={"llm": {"api_key_enc": "not-valid-ciphertext"}})

    with pytest.raises(ValueError):
        await resolve_policy(pg_db, tenant_id=str(tid), dept_id=str(did))


@pytest.mark.asyncio
async def test_invalid_thresholds_revert_to_system_defaults(pg_db):
    # block <= sanitize is invalid; the resolver must revert both to the settings
    # defaults rather than ship an inconsistent policy.
    tid  = await _tenant(pg_db)
    repo = TenantSettingsRepository(pg_db)
    await repo.set(tid, "policy_thresholds", {"block_threshold": 0.3, "sanitize_threshold": 0.5})
    await pg_db.commit()

    s = get_settings()
    policy, _ = await resolve_policy(pg_db, tenant_id=str(tid))

    assert policy["thresholds"]["block"] == s.block_threshold
    assert policy["thresholds"]["sanitize"] == s.sanitize_threshold


# These two used to assert the OPPOSITE: that a department or application load
# failure was swallowed and the system defaults returned as though resolution had
# succeeded. That was the defect -- an override that failed to load may have
# TIGHTENED the policy, and serving the un-tightened base silently relaxed the
# tenant that asked for more strictness. They are re-pinned to the corrected
# contract rather than removed, so the old behaviour cannot return unnoticed.


@pytest.mark.asyncio
async def test_a_bad_dept_id_refuses_rather_than_falling_back(pg_db):
    with pytest.raises(PolicyResolutionDegraded) as refused:
        await resolve_policy(pg_db, dept_id="not-a-uuid")

    assert "department" in refused.value.failed_layers


@pytest.mark.asyncio
async def test_a_bad_app_id_refuses_rather_than_falling_back(pg_db):
    tid = await _tenant(pg_db)

    with pytest.raises(PolicyResolutionDegraded) as refused:
        await resolve_policy(pg_db, tenant_id=str(tid), app_id="not-a-uuid")

    assert "application" in refused.value.failed_layers


@pytest.mark.asyncio
async def test_the_same_failure_is_rendered_not_refused_for_a_preview(pg_db):
    """The other half of the decision: a preview renders the policy, it does not
    apply it, so it degrades visibly instead of refusing."""
    policy, source, degraded = await resolve_policy_for_preview(pg_db, dept_id="not-a-uuid")

    assert degraded is True
    assert source == "degraded"
    assert policy["thresholds"]["block"] == get_settings().block_threshold
