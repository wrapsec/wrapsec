# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
A cached response body cannot outlive the response contract it was built for.

The semantic cache stores a fully-formed response and serves it without
re-deriving anything, and its TTL is an hour. A deployment that changes the shape
of a scan response therefore inherits bodies built by the previous build, and
nothing on the hit path would notice: the caller just receives the older shape.
Waiting out the TTL is not a migration, and validating the cached body against
the new contract does not close it either -- a body that gained a field validates
fine and is served anyway.

`RESPONSE_CONTRACT_VERSION` is carried in the cache key so entries from a
superseded contract are simply not addressable by a newer build.

The observable used here is the audit row's `policy_source`: the hit path records
"cache" and the fresh path records the resolved policy layer, so the two are
distinguishable without depending on response values or on Redis internals.

WARM-UP. Every test here needs its first measured scan to be cacheable, and only
an ALLOW is cached. The first scan in a fresh process loads the transformer, which
can exceed `detector_timeout_seconds` (2.0s); the gateway then fail-closes to
BLOCK, correctly, and caches nothing. Whichever test ran first therefore failed on
a missing cache hit that had nothing to do with the contract version -- and only
when this file ran first, which made it look like a flake. Each test warms the
pipeline with a throwaway scan and then asserts its measured scan was ALLOW, so a
broken premise reports itself instead of being read as a cache defect.
"""

import hashlib
import uuid

import pytest
from sqlalchemy import select

from cache import semantic_cache
from db.models import AuditLogModel


async def _seed_key(test_db):
    from db.models import APIKeyModel, DepartmentModel
    from db.repositories.tenant import TenantRepository

    tenant = await TenantRepository(test_db).get_bootstrap_default()
    assert tenant is not None

    dept_id = uuid.uuid4()
    test_db.add(DepartmentModel(
        id=dept_id, tenant_id=tenant.id, slug=f"cv-{dept_id.hex[:8]}",
        name="Contract version dept", is_active=True,
    ))
    await test_db.flush()

    raw = "wsk_live_" + uuid.uuid4().hex
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:8],
        tenant_id=tenant.id, dept_id=dept_id, app_id=None, name="cv",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
    ))
    await test_db.commit()
    return {"x-api-key": raw}, tenant.id


# Unique prompt text must not look like PII. A raw `uuid4().hex` is a 32-character
# alphanumeric run, and roughly 5% of them match the IBAN_STRICT pattern: the scan
# then returns SANITIZE, only ALLOW is cached, and the test fails perhaps one run
# in five on data it generated itself. Mapping the digits out leaves the value
# unique and unmistakable for an account number (0 of 500 flagged).
_NO_DIGITS = str.maketrans("0123456789", "ghijklmnop")


def _unique() -> str:
    return uuid.uuid4().hex.translate(_NO_DIGITS)


async def _warm_up(client, headers):
    """One throwaway scan, so the measured scan is not the one that pays model
    load. Its own outcome is deliberately ignored -- it may itself fail closed."""
    await client.post(
        "/v1/ai/request", json={"input": f"warm up {_unique()}"}, headers=headers,
    )


def _assert_cacheable(response):
    """Only an ALLOW is written to the cache, so a BLOCK makes every assertion
    below vacuous. Checked explicitly rather than inferred from a missing hit."""
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "ALLOW", (
        f"the measured scan was {response.json()['decision']}, not ALLOW, so "
        "nothing was cached and this test's premise does not hold "
        f"(reason={response.json().get('primary_reason')})"
    )


async def _policy_sources(test_db, tenant_id):
    rows = (await test_db.execute(
        select(AuditLogModel)
        .where(AuditLogModel.tenant_id == str(tenant_id))
        .order_by(AuditLogModel.created_at)
    )).scalars().all()
    return [r.policy_source for r in rows]


# ── the key itself ───────────────────────────────────────────────────────────

def test_the_version_is_part_of_the_key():
    args = {"text": "hello", "detection_mode": "fast", "execution_mode": "scan_only",
            "tenant_id": "t1", "policy_id": "p1", "input_source": "user_prompt"}
    key_v1 = semantic_cache._cache_key(**args)

    assert f"v{semantic_cache.RESPONSE_CONTRACT_VERSION}:" in key_v1, (
        "the contract version must be readable in the key, so entries from a "
        "superseded contract can be found and purged by prefix"
    )


def test_bumping_the_version_changes_the_key(monkeypatch):
    args = {"text": "hello", "detection_mode": "fast", "execution_mode": "scan_only",
            "tenant_id": "t1", "policy_id": "p1", "input_source": "user_prompt"}
    before = semantic_cache._cache_key(**args)

    monkeypatch.setattr(semantic_cache, "RESPONSE_CONTRACT_VERSION",
                        semantic_cache.RESPONSE_CONTRACT_VERSION + 1)
    after = semantic_cache._cache_key(**args)

    assert before != after


def test_the_version_does_not_disturb_policy_identity(monkeypatch):
    """The two answer different questions and must stay independent: bumping the
    response contract must not look like a policy change."""
    identity = {
        "block_threshold": 0.7, "sanitize_threshold": 0.4,
        "pii_block_threshold": None, "pii_sanitize_threshold": None,
        "toxicity_block_threshold": None, "toxicity_sanitize_threshold": None,
        "rule_enabled": True, "ml_enabled": True, "llm_enabled": False,
        "llm_settings": {},
    }
    before = semantic_cache.policy_identity(**identity)
    monkeypatch.setattr(semantic_cache, "RESPONSE_CONTRACT_VERSION",
                        semantic_cache.RESPONSE_CONTRACT_VERSION + 99)

    assert semantic_cache.policy_identity(**identity) == before


# ── the transition, end to end ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_same_version_still_serves_the_cache(client, test_db):
    """The control for the test below: without a version change the second scan
    is answered from the cache. Without this, a bumped version proving a miss
    would prove nothing, because a miss is also what a broken cache produces."""
    headers, tenant_id = await _seed_key(test_db)
    await _warm_up(client, headers)
    prompt = f"contract version control {_unique()}"

    _assert_cacheable(await client.post("/v1/ai/request", json={"input": prompt},
                                        headers=headers))
    assert (await client.post("/v1/ai/request", json={"input": prompt},
                              headers=headers)).status_code == 200

    sources = await _policy_sources(test_db, tenant_id)
    assert sources[-1] == "cache", (
        f"the repeat scan was not served from the cache (sources={sources}); "
        "the transition test below cannot distinguish a version miss from this"
    )


@pytest.mark.asyncio
async def test_a_new_contract_version_does_not_serve_the_old_body(client, test_db, monkeypatch):
    """The requirement: a body cached under version N is not served under N+1."""
    headers, tenant_id = await _seed_key(test_db)
    await _warm_up(client, headers)
    prompt = f"contract version transition {_unique()}"

    first = await client.post("/v1/ai/request", json={"input": prompt}, headers=headers)
    _assert_cacheable(first)

    monkeypatch.setattr(semantic_cache, "RESPONSE_CONTRACT_VERSION",
                        semantic_cache.RESPONSE_CONTRACT_VERSION + 1)

    second = await client.post("/v1/ai/request", json={"input": prompt}, headers=headers)

    assert second.status_code == 200, "the stale entry must not break the request"
    sources = await _policy_sources(test_db, tenant_id)
    assert "cache" not in sources, (
        f"a body cached under the previous contract was served under the new "
        f"one (policy_source={sources})"
    )
    assert second.json()["trace_id"] != first.json()["trace_id"]


@pytest.mark.asyncio
async def test_the_old_entry_is_left_behind_not_broken(client, test_db, monkeypatch):
    """Reverting the version finds the original entry still usable, which is what
    makes this a key-addressing change rather than an invalidation: a rollback
    does not force every tenant to rescan."""
    headers, tenant_id = await _seed_key(test_db)
    await _warm_up(client, headers)
    prompt = f"contract version rollback {_unique()}"

    _assert_cacheable(
        await client.post("/v1/ai/request", json={"input": prompt}, headers=headers)
    )

    original = semantic_cache.RESPONSE_CONTRACT_VERSION
    monkeypatch.setattr(semantic_cache, "RESPONSE_CONTRACT_VERSION", original + 1)
    await client.post("/v1/ai/request", json={"input": prompt}, headers=headers)

    monkeypatch.setattr(semantic_cache, "RESPONSE_CONTRACT_VERSION", original)
    await client.post("/v1/ai/request", json={"input": prompt}, headers=headers)

    sources = await _policy_sources(test_db, tenant_id)
    assert sources[-1] == "cache", (
        f"reverting the contract version did not find the original entry "
        f"(sources={sources})"
    )
