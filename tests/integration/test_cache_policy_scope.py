# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
A cached verdict must not cross a policy scope, checked at the CALL SITE.

`policy_identity` and `_cache_key` are unit-tested, and dropping any component
from the key fails those tests. That establishes the function composes a correct
key and nothing about the endpoint passing it the policy it actually resolved.
Replacing `_policy_id` with a constant in `ai.py` left 32 unit and 724
integration tests green -- the scan endpoint could have keyed every caller's
cache on one value, and a department with stricter policy would have been served
a laxer one's cached ALLOW without its own policy ever being consulted.

Observed through the keyspace rather than the verdict. Two departments that
resolve to different policy must produce two entries for identical input; if the
second is served from the first's entry, no second key appears. That is the
same signal `_assert_served_from_cache` uses in the layer-score tests, read the
other way round.
"""

import hashlib
import uuid

import pytest

_INPUT = {"input": "Please summarise the quarterly report for the team."}


async def _cache_keys() -> set:
    from cache.redis_client import get_redis

    return set(await get_redis().keys("prompt_cache:*"))


async def _clear_cache() -> None:
    from cache.redis_client import get_redis

    redis = get_redis()
    keys = await redis.keys("prompt_cache:*")
    if keys:
        await redis.delete(*keys)


async def _seed_two_depts(test_db, *, override_b) -> tuple[dict, dict]:
    """
    Two live keys in ONE tenant, in departments that resolve differently.

    Same tenant matters: `tenant_id` is a separate component of the key, so two
    tenants would produce two entries whatever the policy did, and the test
    would pass without the policy component existing at all.
    """
    from db.models import APIKeyModel, DepartmentModel, TenantModel

    tid = uuid.uuid4()
    test_db.add(TenantModel(id=tid, slug=f"pol-{tid.hex[:8]}", name="Policy scope"))
    await test_db.commit()

    def _dept(override):
        did = uuid.uuid4()
        test_db.add(DepartmentModel(
            id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}", name="D",
            is_active=True, policy_override=override,
        ))
        return did

    did_a, did_b = _dept(None), _dept(override_b)
    await test_db.commit()

    def _key(did):
        raw = "wsk_live_" + uuid.uuid4().hex
        test_db.add(APIKeyModel(
            id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:8],
            tenant_id=tid, dept_id=did, name="k",
            key_hash=hashlib.sha256(raw.encode()).hexdigest(),
            key_type="live", is_admin=False, revoked=False,
        ))
        return {"x-api-key": raw}

    headers = _key(did_a), _key(did_b)
    await test_db.commit()
    return headers


@pytest.mark.asyncio
async def test_a_stricter_department_is_not_served_a_laxer_ones_cached_verdict(
    client, test_db,
):
    # A department that disables a detection layer resolves to different policy,
    # so its verdict was reached under different rules and is not interchangeable.
    headers_a, headers_b = await _seed_two_depts(
        test_db, override_b={"detection": {"llm_enabled": False}},
    )
    await _clear_cache()

    first = await client.post("/v1/ai/request", json=_INPUT, headers=headers_a)
    assert first.status_code == 200, first.text
    assert first.json()["decision"] == "ALLOW", (
        "only ALLOW is cached, so a flagged probe leaves nothing behind and the "
        "second request cannot be a hit either way"
    )
    after_a = await _cache_keys()
    assert after_a, "the first department's verdict was not cached"

    second = await client.post("/v1/ai/request", json=_INPUT, headers=headers_b)
    assert second.status_code == 200, second.text
    after_b = await _cache_keys()

    assert after_b - after_a, (
        "the second department was served the first one's cached verdict: no "
        "separate cache entry was written, so its own policy never decided"
    )


@pytest.mark.asyncio
async def test_the_same_policy_scope_still_shares_one_entry(client, test_db):
    """
    The other direction. A key that varied per request would also satisfy the
    test above while making the cache useless -- every scan a miss, and the
    invariant trivially true.
    """
    headers_a, _ = await _seed_two_depts(test_db, override_b=None)
    await _clear_cache()

    first = await client.post("/v1/ai/request", json=_INPUT, headers=headers_a)
    assert first.status_code == 200, first.text
    assert first.json()["decision"] == "ALLOW"
    after_first = await _cache_keys()
    assert after_first

    second = await client.post("/v1/ai/request", json=_INPUT, headers=headers_a)
    assert second.status_code == 200, second.text

    assert await _cache_keys() == after_first, (
        "an identical request in the same scope wrote a second cache entry, so "
        "the cache is not being read at all"
    )


@pytest.mark.asyncio
async def test_the_same_text_from_a_different_source_is_a_separate_entry(
    client, test_db,
):
    """
    `input_source` is the other component the call site has to pass. Content an
    agent retrieved may be judged against lower thresholds than the same words
    typed by the user, so the two verdicts are not interchangeable either.
    """
    headers_a, _ = await _seed_two_depts(test_db, override_b=None)
    await _clear_cache()

    first = await client.post(
        "/v1/ai/request", json={**_INPUT, "input_source": "user_prompt"},
        headers=headers_a,
    )
    assert first.status_code == 200, first.text
    assert first.json()["decision"] == "ALLOW"
    after_first = await _cache_keys()
    assert after_first

    second = await client.post(
        "/v1/ai/request", json={**_INPUT, "input_source": "retrieved_document"},
        headers=headers_a,
    )
    assert second.status_code == 200, second.text

    assert await _cache_keys() - after_first, (
        "retrieved content was served a verdict reached for a user prompt"
    )
