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


async def _seed_key_pair(test_db) -> tuple[dict, dict]:
    """
    A LIVE key and a TRIAL key in the same tenant AND the same department.

    Both halves matter, because the cache key is built from the tenant plus the
    resolved policy identity. Same tenant alone is not enough: two departments
    can resolve to different policy, and the callers would then write separate
    entries and never meet.

    The warming caller must not be the admin key. `_authenticate_admin_key`
    leaves `tenant_id` as None under TESTING (`middleware/auth.py:648`), so it
    scans as tenant "global" while any seeded key scans as the real tenant --
    different cache keys, no shared entry, and the unauthorized caller below
    silently exercises the FRESH path instead of the cache-hit one. A live key
    resolves to DEVELOPER and holds `settings:read`, which is the authorization
    this pair is contrasting.
    """
    import hashlib

    from db.models import DepartmentModel
    from db.repositories.tenant import TenantRepository

    tenant = await TenantRepository(test_db).get_bootstrap_default()
    assert tenant is not None, "the default tenant is seeded by the session fixture"

    # `ck_api_keys_non_admin_tenant` requires a department on any non-admin
    # key, so one is created rather than passing dept_id=None.
    dept_id = uuid.uuid4()
    test_db.add(DepartmentModel(
        id        = dept_id,
        tenant_id = tenant.id,
        name      = "cache isolation dept",
        slug      = f"cache-iso-{dept_id.hex[:8]}",
        is_active = True,
    ))
    await test_db.flush()

    def _add(prefix: str, key_type: str) -> str:
        raw = prefix + uuid.uuid4().hex
        test_db.add(APIKeyModel(
            id        = uuid.uuid4(),
            key_id    = f"k_{key_type}_" + uuid.uuid4().hex[:10],
            tenant_id = tenant.id,
            dept_id   = dept_id,
            name      = f"cache isolation {key_type} key",
            key_hash  = hashlib.sha256(raw.encode()).hexdigest(),
            key_type  = key_type,
            is_admin  = False,
            revoked   = False,
        ))
        return raw

    live  = _add("wsk_live_",  "live")
    trial = _add("wsk_trial_", "trial")
    await test_db.commit()
    return {"x-api-key": live}, {"x-api-key": trial}


def _scores(body: dict) -> list:
    return [layer.get("score") for layer in body["assessment"]["layers"]]


async def _cache_keys() -> set:
    from cache.redis_client import get_redis

    return set(await get_redis().keys("prompt_cache:*"))


async def _assert_served_from_cache(before: set) -> None:
    """
    The second caller must have READ the warmed entry, not written its own.

    Asserting that something is in the cache is not the same as asserting this
    request came out of it. When the two callers disagree on tenant or resolved
    policy they compute different cache keys, so the second one misses, scans
    fresh, and stores a SECOND entry -- while every assertion about the
    cache-hit path passes having exercised only the fresh one. A new key
    appearing is exactly that miss, and is what this catches.
    """
    after = await _cache_keys()
    assert after == before, (
        "the request wrote a new cache entry instead of reading the warmed one, "
        "so it missed the cache and the cache-hit path is not under test "
        f"(new: {sorted(after - before)})"
    )


async def _fresh_payload(label: str) -> dict:
    """
    A benign, cacheable input, with the prompt cache cleared first.

    Uniqueness used to come from a `uuid4().hex` in the text. That is a 32-char
    hex blob, which the PII detector reads as a secret, so the verdict was
    SANITIZE and nothing was cached -- every assertion about the cache-hit path
    then ran against an ordinary fresh scan. Plain words keep the verdict ALLOW;
    clearing the keyspace is what makes the first request a miss.
    """
    from cache.redis_client import get_redis

    redis = get_redis()
    keys  = await redis.keys("prompt_cache:*")
    if keys:
        await redis.delete(*keys)
    return {"input": f"Please summarise the quarterly {label} report for the team."}


async def _assert_cached(body_json: dict, payload: dict) -> None:
    """
    Fail loudly if the first request did not populate the cache.

    Only ALLOW verdicts are cached, so a first request the detectors flag leaves
    nothing behind -- the second is then an ordinary fresh scan and every
    assertion about the cache-hit path passes having exercised none of it. That
    is how a test keeps reporting green over a defect it no longer reaches.
    """
    from cache.redis_client import get_redis

    assert body_json.get("decision") == "ALLOW", (
        f"the probe input was not ALLOW ({body_json.get('decision')}), so nothing "
        f"was cached and the cache-hit path is not under test: {payload['input']!r}"
    )
    keys = await get_redis().keys("prompt_cache:*")
    assert keys, "no cache entry was written, so the next request will not be a hit"


@pytest.mark.asyncio
async def test_a_trial_caller_cannot_read_scores_from_a_warm_cache(
    client, test_db,
):
    live_headers, trial_headers = await _seed_key_pair(test_db)

    # Same text, same tenant, same department, same modes -> the same cache key.
    payload = await _fresh_payload("isolation")

    warm = await client.post("/v1/ai/request", json=payload, headers=live_headers)
    assert warm.status_code == 200, warm.text
    assert any(s is not None for s in _scores(warm.json())), (
        "the authorized caller did not receive scores, so this proves nothing "
        "about what the cache then holds"
    )
    await _assert_cached(warm.json(), payload)
    warmed = await _cache_keys()

    served = await client.post("/v1/ai/request", json=payload, headers=trial_headers)
    assert served.status_code == 200, served.text
    await _assert_served_from_cache(warmed)
    body = served.json()

    assert _scores(body) == [None] * len(body["assessment"]["layers"]), (
        "a trial caller read per-layer scores out of a cache entry warmed by an "
        "authorized one"
    )
    for layer in body["assessment"]["layers"]:
        assert "score" not in layer


@pytest.mark.asyncio
async def test_the_warm_cache_still_serves_an_authorized_caller_its_scores(
    client, test_db,
):
    """
    The other direction. Restricting on serve must not have stripped the entry
    itself -- if it had, the first unauthorized caller would silently degrade
    every authorized one after it.
    """
    live_headers, _ = await _seed_key_pair(test_db)
    payload = await _fresh_payload("isolation")

    first = await client.post("/v1/ai/request", json=payload, headers=live_headers)
    assert first.status_code == 200, first.text
    await _assert_cached(first.json(), payload)
    warmed = await _cache_keys()

    second = await client.post("/v1/ai/request", json=payload, headers=live_headers)
    assert second.status_code == 200, second.text
    await _assert_served_from_cache(warmed)
    assert any(s is not None for s in _scores(second.json())), (
        "an authorized caller lost scores on a cache hit"
    )


@pytest.mark.asyncio
async def test_a_trial_caller_still_receives_a_usable_verdict(client, test_db):
    """
    The restriction removes a targeting signal, not the answer. An agent acting
    on the verdict -- which is what the MCP tool does -- must still be able to.
    """
    _, trial_headers = await _seed_key_pair(test_db)
    resp = await client.post(
        "/v1/ai/request",
        json=await _fresh_payload("verdict"),
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


# ---------------------------------------------------------------------------
# A cache hit must not let the caller choose the audit key.
#
# `audit_logs.trace_id` is UNIQUE and String(50); the `X-Trace-Id` header the
# middleware accepts allows up to 64 characters. While the cache-hit path used
# `request.state.trace_id` for the audit row, a caller could pick that key:
# repeat one and the insert violates the constraint, send a 51-character one and
# it overflows the column. Both fail the request, and the caller arranges both.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_repeated_client_trace_id_cannot_break_a_cache_hit(client, admin_headers):
    payload = await _fresh_payload("trace")
    chosen  = "req_" + uuid.uuid4().hex          # valid for the header pattern

    warm = await client.post("/v1/ai/request", json=payload,
                             headers={**admin_headers, "X-Trace-Id": chosen})
    assert warm.status_code == 200, warm.text
    await _assert_cached(warm.json(), payload)
    warmed = await _cache_keys()

    # Same header again, now served from cache -- the path that used to key the
    # audit row on this value.
    again = await client.post("/v1/ai/request", json=payload,
                              headers={**admin_headers, "X-Trace-Id": chosen})
    assert again.status_code == 200, (
        f"a repeated client trace id broke the request: {again.status_code} {again.text[:200]}"
    )
    await _assert_served_from_cache(warmed)
    assert again.json()["trace_id"] != chosen, (
        "the response is keyed on the client's value, so it is still the audit key"
    )


@pytest.mark.asyncio
async def test_an_over_long_client_trace_id_cannot_break_a_cache_hit(client, admin_headers):
    """
    64 characters passes the middleware's pattern and overflows a String(50)
    column. Two requests, because the failure was on the cache-hit insert.
    """
    payload = await _fresh_payload("length")
    over_long = "req_" + ("a" * 60)              # 64 chars: header ok, column not
    assert len(over_long) == 64

    first = await client.post("/v1/ai/request", json=payload,
                              headers={**admin_headers, "X-Trace-Id": over_long})
    assert first.status_code == 200, first.text
    await _assert_cached(first.json(), payload)
    warmed = await _cache_keys()

    second = await client.post("/v1/ai/request", json=payload,
                               headers={**admin_headers, "X-Trace-Id": over_long})
    assert second.status_code == 200, (
        f"an over-long client trace id broke the cached request: "
        f"{second.status_code} {second.text[:200]}"
    )
    await _assert_served_from_cache(warmed)
    assert len(second.json()["trace_id"]) <= 50


@pytest.mark.asyncio
async def test_a_cache_hit_is_still_retrievable_by_the_trace_id_it_returns(
    client, admin_headers,
):
    """
    The generated id must be the one actually written, or the response hands
    back a key that resolves to nothing.
    """
    payload = await _fresh_payload("lookup")
    warm = await client.post("/v1/ai/request", json=payload, headers=admin_headers)
    assert warm.status_code == 200, warm.text
    await _assert_cached(warm.json(), payload)
    warmed = await _cache_keys()

    hit = await client.post("/v1/ai/request", json=payload, headers=admin_headers)
    assert hit.status_code == 200
    await _assert_served_from_cache(warmed)

    found = await client.get(f"/v1/ai/requests/{hit.json()['trace_id']}",
                             headers=admin_headers)
    assert found.status_code == 200, (
        "the cache-hit response returned a trace id with no audit row behind it"
    )
