# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Per-layer scores must not reach an unauthorized caller through the CACHE.

The restriction is applied on SERVE, not on store: the cache holds full bodies,
and each of the two ways out of the handler -- the fresh path and the cache-hit
path -- filters under the same flag. That is a deliberate choice. A live API key
resolves to DEVELOPER, which holds `settings:read`, so nearly all scan traffic
is authorized; caching stripped bodies would take scores away from that majority
on every hit and make one caller's response depend on who scanned first.

What makes it safe is that there are exactly two exits and both filter. The
failure mode is a THIRD exit added later without one, and that is what this
covers: an authorized caller warms the cache with a full body, then an
unauthorized caller scans the identical input inside the TTL and must still not
see a score.

Runs against real Redis, because the defect being guarded lives in the
interaction between the cache and the response filter, not in either alone.
"""

import uuid

import pytest

from db.models import APIKeyModel


async def _seed_trial_key(test_db) -> dict:
    """A trial key in the same tenant, which is what makes the cache shared."""
    import hashlib

    from db.repositories.tenant import TenantRepository

    tenant = await TenantRepository(test_db).get_bootstrap_default()
    assert tenant is not None, "the default tenant is seeded by the session fixture"

    # `ck_api_keys_non_admin_tenant` requires a department on any non-admin
    # key, so one is created rather than passing dept_id=None.
    from db.models import DepartmentModel

    dept_id = uuid.uuid4()
    test_db.add(DepartmentModel(
        id        = dept_id,
        tenant_id = tenant.id,
        name      = "cache isolation dept",
        slug      = f"cache-iso-{dept_id.hex[:8]}",
        is_active = True,
    ))
    await test_db.flush()

    raw = "wsk_trial_" + uuid.uuid4().hex
    test_db.add(APIKeyModel(
        id        = uuid.uuid4(),
        key_id    = "k_trial_" + uuid.uuid4().hex[:10],
        tenant_id = tenant.id,
        dept_id   = dept_id,
        name      = "cache isolation trial key",
        key_hash  = hashlib.sha256(raw.encode()).hexdigest(),
        key_type  = "trial",
        is_admin  = False,
        revoked   = False,
    ))
    await test_db.commit()
    return {"x-api-key": raw}


def _scores(body: dict) -> list:
    return [layer.get("score") for layer in body["assessment"]["layers"]]


@pytest.mark.asyncio
async def test_a_trial_caller_cannot_read_scores_from_a_warm_cache(
    client, admin_headers, test_db,
):
    trial_headers = await _seed_trial_key(test_db)

    # Same text, same tenant, same modes -> the same cache key. Unique per run
    # so a previous run's entry cannot make this pass or fail by accident.
    payload = {"input": f"cache isolation probe {uuid.uuid4().hex}"}

    warm = await client.post("/v1/ai/request", json=payload, headers=admin_headers)
    assert warm.status_code == 200, warm.text
    assert any(s is not None for s in _scores(warm.json())), (
        "the authorized caller did not receive scores, so this proves nothing "
        "about what the cache then holds"
    )

    served = await client.post("/v1/ai/request", json=payload, headers=trial_headers)
    assert served.status_code == 200, served.text
    body = served.json()

    assert _scores(body) == [None] * len(body["assessment"]["layers"]), (
        "a trial caller read per-layer scores out of a cache entry warmed by an "
        "authorized one"
    )
    for layer in body["assessment"]["layers"]:
        assert "score" not in layer


@pytest.mark.asyncio
async def test_the_warm_cache_still_serves_an_authorized_caller_its_scores(
    client, admin_headers,
):
    """
    The other direction. Restricting on serve must not have stripped the entry
    itself -- if it had, the first unauthorized caller would silently degrade
    every authorized one after it.
    """
    payload = {"input": f"cache isolation probe {uuid.uuid4().hex}"}

    first  = await client.post("/v1/ai/request", json=payload, headers=admin_headers)
    second = await client.post("/v1/ai/request", json=payload, headers=admin_headers)

    assert first.status_code == second.status_code == 200
    assert any(s is not None for s in _scores(second.json())), (
        "an authorized caller lost scores on a cache hit"
    )


@pytest.mark.asyncio
async def test_a_trial_caller_still_receives_a_usable_verdict(client, test_db):
    """
    The restriction removes a targeting signal, not the answer. An agent acting
    on the verdict -- which is what the MCP tool does -- must still be able to.
    """
    trial_headers = await _seed_trial_key(test_db)
    resp = await client.post(
        "/v1/ai/request",
        json={"input": f"usable verdict probe {uuid.uuid4().hex}"},
        headers=trial_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["decision"] in ("ALLOW", "SANITIZE", "BLOCK")
    assert isinstance(body["risk_score"], (int, float))
    assert "assessment" in body
    assessment = body["assessment"]
    for field in ("decision", "risk_score", "primary_reason", "confidence", "threats", "layers"):
        assert field in assessment, f"assessment lost {field}"
    for layer in assessment["layers"]:
        assert "name" in layer and "decision" in layer, (
            "classification must survive -- it is what an agent reasons about"
        )
