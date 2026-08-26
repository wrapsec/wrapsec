# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The scan family's response models are applied by the runtime, not just advertised.

A route may declare `response_model` and still return a constructed
`JSONResponse`, in which case FastAPI skips validation and field filtering
entirely while OpenAPI keeps advertising the model. Everything here runs over
real HTTP against the real routes, so it fails if a success return is changed
back to a Response object -- which is the whole point.

The instrument is an UNDECLARED FIELD. `_build_response` is wrapped to add a key
no model declares, and the caller must never see it. With the model applied the
key is dropped; with a `JSONResponse` it is served. One assertion, and it can
only be satisfied one way.

Three exits are covered separately because they are three different code paths:
the fresh scan, the CACHE HIT (a body built by an earlier request, possibly an
earlier build), and the batch. The read-back route is covered by type, since its
body is assembled inline from a database row rather than by a shared helper.

Absence and null are checked as well. They are not decoration: `layers[].score`
must be ABSENT for a restricted caller, while `summary.highest_risk_item` must be
NULL rather than absent when nothing scored. A model that confused the two would
pass a shape test and break both contracts.
"""

import uuid

import pytest

_LEAK = "undeclared_internal_field"

_NO_DIGITS = str.maketrans("0123456789", "ghijklmnop")


def _unique() -> str:
    """Unique, and not shaped like an account number -- a raw hex blob reads as
    PII to the guardrail, which turns the verdict into SANITIZE."""
    return uuid.uuid4().hex.translate(_NO_DIGITS)


@pytest.fixture
async def live_key_headers(test_db):
    """A live key seeded for THIS test, rather than the shared admin key.

    Two reasons, and the second is why the fixture exists at all:

      * the rate limiter buckets on `sha256(x-api-key)`, so every test using
        `admin_headers` shares one 60/min budget. This file is request-heavy, and
        adding it to that shared bucket pushed unrelated files in the same run
        over the limit -- their failures said RATE_LIMIT_EXCEEDED, which looks
        like a regression and is not one. A key per test is a bucket per test;
      * the admin key scans as tenant "global" under TESTING while a seeded key
        scans as the real tenant, which matters for anything the cache keys on.
    """
    import hashlib

    from db.models import APIKeyModel, DepartmentModel
    from db.repositories.tenant import TenantRepository

    tenant = await TenantRepository(test_db).get_bootstrap_default()
    assert tenant is not None, "the default tenant is seeded by the session fixture"

    dept_id = uuid.uuid4()
    test_db.add(DepartmentModel(
        id=dept_id, tenant_id=tenant.id, slug=f"rc-{dept_id.hex[:8]}",
        name="Response contract dept", is_active=True,
    ))
    await test_db.flush()

    raw = "wsk_live_" + uuid.uuid4().hex
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:8],
        tenant_id=tenant.id, dept_id=dept_id, app_id=None, name="response-contract",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
    ))
    await test_db.commit()
    return {"x-api-key": raw}


@pytest.fixture
def leaky_build_response(monkeypatch):
    """Make the handler produce a field no response model declares.

    Patched on the module the endpoints call, so the injection happens exactly
    where a real internal field would appear: inside the body the handler hands
    to FastAPI.
    """
    from api.v1.endpoints import ai

    original = ai._build_response

    def _leaky(*args, **kwargs):
        body = original(*args, **kwargs)
        body[_LEAK] = "must not reach the caller"
        body["assessment"][_LEAK] = "must not reach the caller either"
        return body

    monkeypatch.setattr(ai, "_build_response", _leaky)
    return _leaky


async def _clear_prompt_cache():
    from cache.redis_client import get_redis

    redis = get_redis()
    keys  = await redis.keys("prompt_cache:*")
    if keys:
        await redis.delete(*keys)


# ── runtime enforcement, one exit at a time ──────────────────────────────────

@pytest.mark.asyncio
async def test_a_fresh_scan_drops_an_undeclared_field(client, live_key_headers, leaky_build_response):
    await _clear_prompt_cache()
    r = await client.post("/v1/ai/request",
                          json={"input": f"contract enforcement fresh {_unique()}"},
                          headers=live_key_headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert _LEAK not in body, (
        "an undeclared field reached the caller, so the response model is not "
        "being applied -- the success path is returning a Response object"
    )
    assert _LEAK not in body["assessment"], "nested filtering is not being applied"
    assert body["decision"] in ("ALLOW", "SANITIZE", "BLOCK"), "the real body is still served"


@pytest.mark.asyncio
async def test_a_cache_hit_drops_an_undeclared_field(client, live_key_headers, leaky_build_response):
    """The cached body is built by one request and served to another, so it is
    the exit most likely to carry a field the current contract never declared.
    Here the entry is deliberately warmed WITH the extra field, then read back."""
    await _clear_prompt_cache()
    payload = {"input": f"contract enforcement cached {_unique()}"}

    warm = await client.post("/v1/ai/request", json=payload, headers=live_key_headers)
    assert warm.status_code == 200, warm.text
    assert warm.json().get("decision") == "ALLOW", (
        "only an ALLOW is cached, so this test would not reach the cache-hit path"
    )

    hit = await client.post("/v1/ai/request", json=payload, headers=live_key_headers)
    assert hit.status_code == 200, hit.text
    assert _LEAK not in hit.json(), (
        "a field from the cached body reached the caller unfiltered; the "
        "cache-hit exit is not passing through the response model"
    )


@pytest.mark.asyncio
async def test_a_batch_drops_an_undeclared_field(client, live_key_headers, leaky_build_response):
    r = await client.post(
        "/v1/ai/scan-batch",
        json={"items": [{"input": f"contract enforcement batch {_unique()}"}]},
        headers=live_key_headers,
    )

    assert r.status_code == 200, r.text
    body = r.json()
    assert _LEAK not in body
    assert _LEAK not in body["results"][0]["assessment"], (
        "an undeclared field survived inside a batch item's assessment"
    )


@pytest.mark.asyncio
async def test_the_read_back_refuses_to_serve_a_value_of_the_wrong_type(
    client, live_key_headers, monkeypatch,
):
    """The read-back body is assembled inline from a database row, so the lever
    is the row: a `risk_score` that is not a number must not be served as though
    the contract allowed it. Without the model, the string goes out untouched."""
    from types import SimpleNamespace

    from api.v1.endpoints import ai

    scan = await client.post("/v1/ai/request",
                             json={"input": f"contract enforcement readback {_unique()}"},
                             headers=live_key_headers)
    assert scan.status_code == 200, scan.text
    trace_id = scan.json()["trace_id"]

    original = ai.get_scoped_audit_record

    async def _corrupt(repo, tid, request):
        record = await original(repo, tid, request)
        if record is None:
            return None
        fields = {name: getattr(record, name) for name in dir(record)
                  if not name.startswith("_") and not callable(getattr(record, name, None))}
        fields["risk_score"] = "not-a-number"
        return SimpleNamespace(**fields)

    monkeypatch.setattr(ai, "get_scoped_audit_record", _corrupt)

    # Response validation raises rather than returning, and the test transport
    # re-raises it instead of converting it to a 500 the way a served deployment
    # does. Both outcomes satisfy the claim being made -- the invalid value does
    # not reach the caller -- so both are accepted, and only serving it fails.
    from fastapi.exceptions import ResponseValidationError

    try:
        r = await client.get(f"/v1/ai/requests/{trace_id}", headers=live_key_headers)
    except ResponseValidationError as rejected:
        assert "risk_score" in str(rejected), (
            "response validation rejected the record for some other reason"
        )
        return

    assert r.status_code != 200 or "not-a-number" not in r.text, (
        "a value that violates the declared type was served to the caller, so "
        "the response model is not validating this route"
    )


# ── absence, and the difference between absent and null ──────────────────────

@pytest.mark.asyncio
async def test_optional_fields_stay_absent_rather_than_becoming_null(client, live_key_headers):
    """`response_model_exclude_unset` must not be quietly replaced by a default
    serialization that fills these in as null -- a client checking `"output" in
    body` would then always find it."""
    await _clear_prompt_cache()
    r = await client.post("/v1/ai/request",
                          json={"input": f"absence probe {_unique()}"},
                          headers=live_key_headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "ALLOW", "a clean input is needed for this assertion"
    for field in ("sanitized_input", "output", "debug"):
        assert field not in body, f"{field} appeared on a clean ALLOW, as {body.get(field)!r}"
    assert "posture" not in body["assessment"], (
        "posture appeared for a first-party prompt at the base posture"
    )


@pytest.mark.asyncio
async def test_legitimate_nulls_survive_the_model(client, live_key_headers):
    """The other half of the same mechanism. A batch item sent without an id has
    a null id, and a batch where nothing scored has a null highest_risk_item;
    both keys must still be present."""
    r = await client.post(
        "/v1/ai/scan-batch",
        json={"items": [{"input": f"null preservation {_unique()}"}]},
        headers=live_key_headers,
    )

    assert r.status_code == 200, r.text
    body = r.json()
    assert "highest_risk_item" in body["summary"], "a legitimate null was dropped"
    assert body["summary"]["highest_risk_item"] is None
    assert "id" in body["results"][0], "the echoed id key was dropped instead of being null"
    assert body["results"][0]["id"] is None


@pytest.mark.asyncio
async def test_a_caller_supplied_id_is_echoed_back(client, live_key_headers):
    """Guards the guard above: if `id` were always null the test before this one
    would pass while the field carried nothing."""
    r = await client.post(
        "/v1/ai/scan-batch",
        json={"items": [{"input": f"echo {_unique()}", "id": "chunk-42"}]},
        headers=live_key_headers,
    )

    assert r.status_code == 200, r.text
    assert r.json()["results"][0]["id"] == "chunk-42"


# ── the layer-score boundary, through the endpoint ───────────────────────────

@pytest.mark.asyncio
async def test_the_model_does_not_reintroduce_a_restricted_score_as_null(
    client, scored_key_pair,
):
    """The restriction removes the key. A model that declared `score` non-optional
    would have forced it back in as null or 0.0, which is exactly the leak the
    restriction exists to prevent -- a null still says a score was computed and
    withheld, and clients would have to tell it apart from a real 0.0."""
    live_headers, trial_headers = scored_key_pair
    await _clear_prompt_cache()

    authorized = await client.post("/v1/ai/request",
                                   json={"input": f"score boundary {_unique()}"},
                                   headers=live_headers)
    assert authorized.status_code == 200, authorized.text
    assert all("score" in layer for layer in authorized.json()["assessment"]["layers"]), (
        "the authorized caller lost its scores, so the comparison below is empty"
    )

    restricted = await client.post("/v1/ai/request",
                                   json={"input": f"score boundary {_unique()}"},
                                   headers=trial_headers)
    assert restricted.status_code == 200, restricted.text
    layers = restricted.json()["assessment"]["layers"]
    assert layers, "no layers to check"
    for layer in layers:
        assert "score" not in layer, f"score present for a restricted caller: {layer}"
        assert layer["name"] and layer["decision"], "classification must survive"


@pytest.mark.asyncio
async def test_the_batch_applies_the_same_restriction(client, scored_key_pair):
    """A batch is not a way around the single-scan restriction, and the model
    must not undo it."""
    _, trial_headers = scored_key_pair
    r = await client.post(
        "/v1/ai/scan-batch",
        json={"items": [{"input": f"batch score boundary {_unique()}"}]},
        headers=trial_headers,
    )

    assert r.status_code == 200, r.text
    for layer in r.json()["results"][0]["assessment"]["layers"]:
        assert "score" not in layer


@pytest.mark.asyncio
async def test_the_read_back_keeps_restricted_score_maps_present_but_empty(
    client, scored_key_pair,
):
    """The persisted form of the same numbers. These are emptied rather than
    omitted, deliberately, so a consumer needs no special case -- the model must
    preserve that distinction too."""
    live_headers, trial_headers = scored_key_pair

    scan = await client.post("/v1/ai/request",
                             json={"input": f"read back restriction {_unique()}"},
                             headers=live_headers)
    assert scan.status_code == 200, scan.text
    trace_id = scan.json()["trace_id"]

    authorized = await client.get(f"/v1/ai/requests/{trace_id}", headers=live_headers)
    assert authorized.status_code == 200, authorized.text
    assert authorized.json()["detection_scores"], (
        "the authorized read-back carried no scores, so the check below proves nothing"
    )

    restricted = await client.get(f"/v1/ai/requests/{trace_id}", headers=trial_headers)
    assert restricted.status_code == 200, restricted.text
    body = restricted.json()
    assert body["detection_scores"] == {}, "a restricted caller read back the scores"
    assert body["guardrail_scores"] == {}
    assert "detection_scores" in body and "guardrail_scores" in body, (
        "the keys must stay present and empty, not be dropped"
    )
    assert "proxy" not in body, "proxy detail appeared for a scan-only request"


# ── the declared 422 on the read-back route ──────────────────────────────────

@pytest.mark.asyncio
async def test_the_read_back_success_body_is_unchanged_by_the_declared_422(
    client, live_key_headers,
):
    """Declaring the 422 must not disturb the success contract.

    The 422 entry was added to this route's `responses` map to replace the
    generated `HTTPValidationError`. `responses` documents failures and cannot
    reach the success path, but that is asserted rather than argued: the read-back
    still answers 200 with the same field set the model declares.
    """
    from api.v1.schemas.response import RequestRecordResponse

    scan = await client.post("/v1/ai/request",
                             json={"input": f"declared 422 success probe {_unique()}"},
                             headers=live_key_headers)
    assert scan.status_code == 200, scan.text

    read_back = await client.get(f"/v1/ai/requests/{scan.json()['trace_id']}",
                                 headers=live_key_headers)
    assert read_back.status_code == 200, read_back.text

    served = set(read_back.json())
    declared = set(RequestRecordResponse.model_fields)
    assert served <= declared, f"served fields the model does not declare: {served - declared}"
    assert {"trace_id", "decision", "risk_score", "timestamp"} <= served


@pytest.mark.asyncio
async def test_a_validation_failure_in_this_family_returns_the_catalog_envelope(
    client, live_key_headers,
):
    """The body the declared 422 names, measured on the route that can reach one.

    The read-back route itself CANNOT: its only parameter is an unconstrained path
    string, so nothing about a request to it can fail validation, and its 422 entry
    exists purely to correct the shape FastAPI publishes for any parameterized
    route. The scan route in the same family takes a body and does reject one, so
    it is where the shape is verified -- the handler is global, so one measurement
    covers both.

    `detail` is asserted absent because that is the field a caller coding against
    the old generated schema would have reached for.
    """
    r = await client.post("/v1/ai/request", json={"input": 12345},
                          headers=live_key_headers)

    assert r.status_code == 422, r.text
    body = r.json()
    assert "detail" not in body, "the generated HTTPValidationError shape is back"
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["invalid_params"][0]["field"] == "input"
