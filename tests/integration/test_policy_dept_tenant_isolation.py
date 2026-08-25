# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
A department policy may only be resolved when the department belongs to the
authenticated tenant.

The application branch of `resolve_policy` has always refused a cross-tenant
app; the department branch loaded whatever `dept_id` it was handed. Nothing in
the schema closes that gap -- `api_keys.dept_id` is a plain FK to
`departments.id` with no constraint tying it to `api_keys.tenant_id`, and
`ck_api_keys_non_admin_tenant` only requires that a non-admin key HAS both. So a
department row carrying a foreign tenant is representable, and its thresholds
would have been applied to this tenant's traffic.

The observable used here is the audit row's `policy_source`, not a risk score: it
records which layer actually changed the policy, so it distinguishes "the
override was applied" from "the override was ignored" without depending on where
a detector happens to score a given prompt.
"""

import hashlib
import uuid

import pytest

from services.policy_resolver import resolve_policy

# Thresholds far from the system defaults, so an override that is applied is
# unmistakable in the resolved policy.
_DEPT_OVERRIDE = {"thresholds": {"block": 0.11, "sanitize": 0.05}}


async def _seed_tenant_with_dept(test_db, *, policy_override=None):
    from db.models import DepartmentModel, TenantModel

    tid, did = uuid.uuid4(), uuid.uuid4()
    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await test_db.commit()
    test_db.add(DepartmentModel(
        id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}", name="Eng",
        is_active=True, policy_override=policy_override,
    ))
    await test_db.commit()
    return tid, did


async def _seed_key(test_db, *, tenant_id, dept_id):
    """Seed a hash-matching non-admin key. tenant_id and dept_id are set
    independently on purpose: that is exactly the pairing the schema permits and
    the resolver must not trust."""
    from db.models import APIKeyModel

    raw = "wsk_live_" + uuid.uuid4().hex
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:8],
        tenant_id=tenant_id, dept_id=dept_id, app_id=None, name="k",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
    ))
    await test_db.commit()
    return raw


async def _policy_sources(test_db, tenant_id):
    from sqlalchemy import select

    from db.models import AuditLogModel

    rows = (await test_db.execute(
        select(AuditLogModel).where(AuditLogModel.tenant_id == str(tenant_id))
    )).scalars().all()
    return [row.policy_source for row in rows]


# ── resolver ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_own_department_override_is_applied(test_db):
    """The positive case, so the negative one below cannot pass by the override
    never working at all."""
    tid, did = await _seed_tenant_with_dept(test_db, policy_override=_DEPT_OVERRIDE)

    policy, source = await resolve_policy(
        db=test_db, tenant_id=str(tid), dept_id=str(did), app_id=None,
    )

    assert source == "department_override"
    assert policy["thresholds"]["block"] == 0.11


@pytest.mark.asyncio
async def test_foreign_department_override_is_refused(test_db):
    """The invariant: a department belonging to another tenant contributes
    nothing, even though the caller handed its id in."""
    mine, _  = await _seed_tenant_with_dept(test_db)
    _, their = await _seed_tenant_with_dept(test_db, policy_override=_DEPT_OVERRIDE)

    policy, source = await resolve_policy(
        db=test_db, tenant_id=str(mine), dept_id=str(their), app_id=None,
    )

    assert source == "system_default"
    assert policy["thresholds"]["block"] != 0.11


@pytest.mark.asyncio
async def test_a_missing_department_still_falls_back_cleanly(test_db):
    """The check must not turn an unknown dept_id into an error path."""
    mine, _ = await _seed_tenant_with_dept(test_db)

    policy, source = await resolve_policy(
        db=test_db, tenant_id=str(mine), dept_id=str(uuid.uuid4()), app_id=None,
    )

    assert source == "system_default"
    assert policy["thresholds"]["block"] > 0


@pytest.mark.asyncio
async def test_dept_override_still_applies_when_no_tenant_is_supplied(test_db):
    """The check is conditioned on a known tenant. With none supplied there is no
    boundary to enforce and the override still applies -- documented here so the
    behaviour is deliberate rather than discovered later."""
    _tid, did = await _seed_tenant_with_dept(test_db, policy_override=_DEPT_OVERRIDE)

    policy, source = await resolve_policy(
        db=test_db, tenant_id=None, dept_id=str(did), app_id=None,
    )

    assert source == "department_override"
    assert policy["thresholds"]["block"] == 0.11


# ── the real caller path: dept_id arrives from the API key ───────────────────

@pytest.mark.asyncio
async def test_scan_applies_the_key_own_department_policy(client, test_db):
    tid, did = await _seed_tenant_with_dept(test_db, policy_override=_DEPT_OVERRIDE)
    raw      = await _seed_key(test_db, tenant_id=tid, dept_id=did)

    r = await client.post("/v1/ai/request", json={"input": "hello world"},
                          headers={"x-api-key": raw})

    assert r.status_code == 200
    assert await _policy_sources(test_db, tid) == ["department_override"]


@pytest.mark.asyncio
async def test_scan_refuses_a_foreign_department_carried_by_the_key(client, test_db):
    """The end-to-end claim: a key whose dept_id points into another tenant does
    not get that tenant's thresholds applied to its traffic."""
    mine, _   = await _seed_tenant_with_dept(test_db)
    _, theirs = await _seed_tenant_with_dept(test_db, policy_override=_DEPT_OVERRIDE)
    raw       = await _seed_key(test_db, tenant_id=mine, dept_id=theirs)

    r = await client.post("/v1/ai/request", json={"input": "hello world"},
                          headers={"x-api-key": raw})

    assert r.status_code == 200
    assert await _policy_sources(test_db, mine) == ["system_default"]


@pytest.mark.asyncio
async def test_one_tenant_cached_policy_is_not_served_to_another(client, test_db):
    """Resolution feeds the semantic cache key, so a shared entry would reinstate
    the leak the check just closed: the same prompt, scanned by two tenants, must
    not let the first tenant's resolved policy answer for the second."""
    tid_a, did_a = await _seed_tenant_with_dept(test_db, policy_override=_DEPT_OVERRIDE)
    tid_b, did_b = await _seed_tenant_with_dept(test_db)
    key_a = await _seed_key(test_db, tenant_id=tid_a, dept_id=did_a)
    key_b = await _seed_key(test_db, tenant_id=tid_b, dept_id=did_b)

    prompt = "a shared prompt scanned by both tenants"
    assert (await client.post("/v1/ai/request", json={"input": prompt},
                              headers={"x-api-key": key_a})).status_code == 200
    assert (await client.post("/v1/ai/request", json={"input": prompt},
                              headers={"x-api-key": key_b})).status_code == 200

    # Each tenant is audited under the policy IT resolved. Tenant B has no
    # override, so a "department_override" row here would mean B was served A's.
    assert await _policy_sources(test_db, tid_a) == ["department_override"]
    assert await _policy_sources(test_db, tid_b) == ["system_default"]
