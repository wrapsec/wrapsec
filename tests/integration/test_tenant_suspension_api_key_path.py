# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Suspending a tenant must stop its API keys, not only its dashboard sessions.

`_tenant_suspended` is checked at two places in the middleware: once on the JWT
path and once on the API-key path. The unit tests exercise the FUNCTION, which
establishes what it returns and nothing about either call site, and the
lifecycle rehearsal covers the JWT one by locking out a tenant admin.

Nothing covered the API-key one. Disabling it left the entire suite green, so a
suspended tenant's keys would have kept scanning and proxying while the operator
watched its admin get locked out of the dashboard and reasonably concluded the
suspension had taken effect. That is the path carrying the actual gateway
traffic, and it is the one the kill switch exists for.

The check is asserted here on the endpoints a key can reach, since suspension is
enforced in the middleware and is therefore a property of the credential rather
than of any single route.
"""

import hashlib
import uuid

import pytest

from config.settings import get_settings


def _operator() -> dict:
    return {"x-api-key": get_settings().admin_api_key}


async def _seed_tenant_with_key(test_db) -> tuple[str, dict]:
    """A tenant of its own, so suspending it cannot disturb other tests."""
    from db.models import APIKeyModel, DepartmentModel, TenantModel

    tid, did = uuid.uuid4(), uuid.uuid4()
    raw = "wsk_live_" + uuid.uuid4().hex

    test_db.add(TenantModel(id=tid, slug=f"susp-{tid.hex[:8]}", name="Suspendable"))
    await test_db.commit()
    test_db.add(DepartmentModel(
        id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}", name="Eng", is_active=True,
    ))
    await test_db.commit()
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:8],
        tenant_id=tid, dept_id=did, name="gateway key",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
    ))
    await test_db.commit()
    return str(tid), {"x-api-key": raw}


async def _suspend(client, tenant_id: str) -> None:
    resp = await client.post(
        f"/v1/admin/tenants/{tenant_id}/suspend", headers=_operator(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "suspended"


@pytest.mark.asyncio
async def test_a_suspended_tenants_api_key_cannot_scan(client, test_db):
    tenant_id, key_headers = await _seed_tenant_with_key(test_db)
    payload = {"input": "Please summarise the quarterly report for the team."}

    before = await client.post("/v1/ai/request", json=payload, headers=key_headers)
    assert before.status_code == 200, (
        f"the key could not scan before suspension, so this proves nothing "
        f"about suspension: {before.text[:200]}"
    )

    await _suspend(client, tenant_id)

    after = await client.post("/v1/ai/request", json=payload, headers=key_headers)
    assert after.status_code == 403, (
        f"a suspended tenant's API key still scanned: {after.status_code}"
    )
    assert after.json()["error"]["code"] == "TENANT_SUSPENDED"


@pytest.mark.asyncio
async def test_a_suspended_tenants_api_key_cannot_reach_the_proxy(client, test_db):
    """
    The proxy is the other traffic path a key can take. It is rejected in the
    middleware, before any provider configuration is consulted, so no provider
    needs to exist for this to be the real answer.
    """
    tenant_id, key_headers = await _seed_tenant_with_key(test_db)
    await _suspend(client, tenant_id)

    resp = await client.post(
        "/v1/chat/completions",
        json={"model": "openai/gpt-4o",
              "messages": [{"role": "user", "content": "hello"}]},
        headers=key_headers,
    )
    assert resp.status_code == 403, (
        f"a suspended tenant's API key reached the proxy: {resp.status_code}"
    )


@pytest.mark.asyncio
async def test_reactivation_restores_the_api_key(client, test_db):
    """
    Suspension has to be reversible on this path too, or the check is a
    one-way door and the operator's reactivate button quietly does nothing for
    gateway traffic.
    """
    tenant_id, key_headers = await _seed_tenant_with_key(test_db)
    payload = {"input": "Please summarise the quarterly report for the team."}

    await _suspend(client, tenant_id)
    blocked = await client.post("/v1/ai/request", json=payload, headers=key_headers)
    assert blocked.status_code == 403

    resp = await client.post(
        f"/v1/admin/tenants/{tenant_id}/reactivate", headers=_operator(),
    )
    assert resp.status_code == 200, resp.text

    restored = await client.post("/v1/ai/request", json=payload, headers=key_headers)
    assert restored.status_code == 200, (
        f"reactivation did not restore the key: {restored.status_code} "
        f"{restored.text[:200]}"
    )
