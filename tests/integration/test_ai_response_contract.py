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


# ── shared error paths on the AI family ──────────────────────────────────────

@pytest.mark.asyncio
async def test_reusing_an_idempotency_key_with_a_different_body_is_refused(
    client, live_key_headers,
):
    """409 from the idempotency middleware, which the route never mentions.

    The point of the refusal is that the caller must NOT be handed the first
    body when they asked for something else, so the second request is asserted
    to be rejected rather than served a cached 200.

    Also the leak check for this path: the middleware sees the whole request,
    so its refusal is the natural place for a body or a credential to escape.
    """
    key = f"idem-{_unique()}"
    headers = {**live_key_headers, "Idempotency-Key": key}

    first = await client.post("/v1/ai/request", headers=headers,
                              json={"input": f"idempotency first {_unique()}"})
    assert first.status_code == 200, first.text

    secret = f"second-body-marker-{_unique()}"
    second = await client.post("/v1/ai/request", headers=headers,
                               json={"input": secret, "user_id": "u-idem-probe"})

    assert second.status_code == 409, second.text
    error = second.json()["error"]
    assert error["code"]     == "IDEMPOTENCY_CONFLICT"
    assert error["key"]      == "errors.IDEMPOTENCY_CONFLICT"
    assert error["severity"] == "WARNING"
    assert error["trace_id"].startswith("req_")

    for leaked in (secret, "u-idem-probe", key, live_key_headers["x-api-key"]):
        assert leaked not in second.text, f"the 409 body carried {leaked!r}"


@pytest.mark.asyncio
async def test_the_read_back_shares_the_global_ai_rate_limit(client, live_key_headers):
    """429 on a route that scans nothing.

    The global limiter matches on the `/v1/ai` PREFIX, so this read-back sits in
    the same bucket as the scan routes. That is easy to miss from the route
    source -- it takes no rate-limit dependency of its own -- and it is why the
    status went undeclared here while being declared on its siblings.

    The bucket is keyed on the hashed credential, and this fixture's key is
    unique to the test, so the loop cannot exhaust another test's allowance.
    """
    trace = "req_" + "0" * 32
    refused = None
    for _ in range(130):
        r = await client.get(f"/v1/ai/requests/{trace}", headers=live_key_headers)
        if r.status_code == 429:
            refused = r
            break
        assert r.status_code == 404, r.text   # unknown trace, until the limit bites

    assert refused is not None, "the global /v1/ai bucket was never exhausted"
    error = refused.json()["error"]
    assert error["code"] == "RATE_LIMIT_EXCEEDED"
    assert error["key"]  == "errors.RATE_LIMIT_EXCEEDED"
    assert isinstance(error["params"].get("retry_after"), int)


# ── capability refusals ──────────────────────────────────────────────────────
#
# Two conditions on this route refuse the SAME capability for reasons outside
# the request: a trial credential, and a detection layer disabled by policy. The
# request is well formed in both cases -- a live key on a tenant with the layer
# enabled succeeds with an identical body -- so neither is a validation failure,
# and neither is about the caller's role.
#
# They share one code and one body ON PURPOSE. A caller able to tell them apart
# would be reading tenant configuration out of an error message.

_FEATURE_TERMS = ("trial", "tier", "plan", "upgrade", "subscription", "pricing",
                  "billing", "llm_enabled", "detection", "policy", "tenant")


def _capability_envelope(response):
    assert response.status_code == 403, response.text
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert set(error) == {"code", "severity", "key", "params", "message", "trace_id"}, (
        f"unexpected envelope fields: {sorted(error)}"
    )
    assert error["code"]     == "FEATURE_UNAVAILABLE"
    assert error["key"]      == "errors.FEATURE_UNAVAILABLE"
    assert error["severity"] == "WARNING"
    assert error["params"]   == {"feature": "proxy execution"}
    assert error["message"]  == "proxy execution is not available."
    assert error["trace_id"].startswith("req_")
    # The feature identity is structural. The message is the catalog rendering of
    # key + params, not a sentence written at the call site.
    assert "invalid_params" not in error, (
        "the capability refusal is not a field error; execution_mode is valid"
    )
    return error


@pytest.mark.asyncio
async def test_a_trial_credential_is_refused_the_proxy_capability(client, scored_key_pair):
    """Producer 1. Was `403 FORBIDDEN`, which rendered "You do not have
    permission to perform this action" and sent the reader looking for a role to
    change. Nothing about this caller's role is wrong."""
    _, trial = scored_key_pair

    r = await client.post("/v1/ai/request", headers=trial, json={
        "input": "capability probe", "execution_mode": "proxy", "model": "openai/gpt-4o",
    })

    _capability_envelope(r)


@pytest.mark.asyncio
async def test_a_disabled_detection_layer_refuses_the_proxy_capability(
    client, scored_key_pair, admin_jwt_headers,
):
    """Producer 2. Was `422 VALIDATION_ERROR`, which was wrong twice: the body is
    valid, and `llm_enabled` is resolved policy the caller cannot set and usually
    cannot read."""
    live, _ = scored_key_pair
    off = await client.put("/v1/settings/layers", headers=admin_jwt_headers,
                           json={"llm_enabled": False})
    assert off.status_code == 200, off.text

    r = await client.post("/v1/ai/request", headers=live, json={
        "input": "capability probe", "execution_mode": "proxy", "model": "openai/gpt-4o",
    })

    _capability_envelope(r)


@pytest.mark.asyncio
async def test_the_two_capability_refusals_are_indistinguishable(
    client, scored_key_pair, admin_jwt_headers,
):
    """The security property, asserted rather than argued.

    A trial caller and a live caller on a tenant with the layer switched off must
    receive the same body. If they differed, the response would tell each of them
    something about the deployment they are not entitled to know.
    """
    live, trial = scored_key_pair
    assert (await client.put("/v1/settings/layers", headers=admin_jwt_headers,
                             json={"llm_enabled": False})).status_code == 200

    body = {"input": "same probe", "execution_mode": "proxy", "model": "openai/gpt-4o"}
    a = await client.post("/v1/ai/request", headers=trial, json=body)
    b = await client.post("/v1/ai/request", headers=live,  json=body)

    strip = lambda r: {k: v for k, v in r.json()["error"].items() if k != "trace_id"}
    assert a.status_code == b.status_code == 403
    assert strip(a) == strip(b), (
        "the two capability refusals differ, so the response distinguishes a "
        "credential class from a tenant policy setting"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["trial", "layer-off"])
async def test_the_capability_refusal_leaks_no_cause_or_configuration(
    client, scored_key_pair, admin_jwt_headers, mode,
):
    """No commercial terminology and no configuration reaches the public body.

    The catalog owns the text, and `params` carries a capability NAME rather than
    the flag, the plan or the credential class that decided it. The cause lives
    in `debug_message`, which is logged and never serialized.
    """
    live, trial = scored_key_pair
    if mode == "trial":
        headers = trial
    else:
        headers = live
        assert (await client.put("/v1/settings/layers", headers=admin_jwt_headers,
                                 json={"llm_enabled": False})).status_code == 200

    r = await client.post("/v1/ai/request", headers=headers, json={
        "input": "leak probe", "execution_mode": "proxy", "model": "openai/gpt-4o",
    })

    assert r.status_code == 403
    lowered = r.text.lower()
    for term in _FEATURE_TERMS:
        assert term not in lowered, f"the capability refusal carried {term!r}"
    for term in ("execution_mode", "openai", "gpt-4o", "wsk_", "sk-",
                 "SELECT", "Traceback", "/home/"):
        assert term not in r.text, f"the capability refusal carried {term!r}"


# -- NOT_FOUND resource token -------------------------------------------------

@pytest.mark.asyncio
async def test_an_unknown_trace_names_the_resource_by_token(client, live_key_headers):
    """The read-back 404 names WHAT was missing, as a machine token.

    `request` is already the token spelling, so this pins a value that did not
    change -- which is exactly why it is worth pinning: nothing in the diff
    would reveal it drifting to prose later.
    """
    ghost = "req_00000000000000000000000000000000"
    r = await client.get(f"/v1/ai/requests/{ghost}", headers=live_key_headers)

    assert r.status_code == 404, r.text
    error = r.json()["error"]
    assert error["code"]   == "NOT_FOUND"
    assert error["key"]    == "errors.NOT_FOUND"
    assert error["params"] == {"resource": "request"}
    # The requested trace is not echoed; the caller correlates on the envelope's
    # own trace_id instead.
    assert ghost not in r.text
    assert error["trace_id"] != ghost


# ── the scan route refuses a body the model cannot accept ────────────────────
#
# The three tests above prove FILTERING on this route: a field the model does
# not declare is stripped. That is a different property from REJECTION, and only
# rejection shows the model is validating rather than just projecting. The
# read-back route has a type probe already; the scan route, the busiest exit in
# the API, had none.
#
# Each patches `_build_response`, which is where a real writer bug would sit,
# and each corrupts one thing so the failure names it. The corrupted body is
# also what gets CACHED, so every one of these uses a unique input -- a poisoned
# entry under a shared key would surface as an unrelated failure later in the
# run.


async def _scan_rejects(client, headers, corrupt, expect_named, monkeypatch):
    """Corrupt the scan writer, then assert the caller never sees the result.

    Validation raises rather than returning, and the test transport re-raises
    instead of converting it to the 500 a served deployment returns. Both
    outcomes satisfy the claim -- the invalid body did not reach the caller.

    What is NOT accepted is a clean 200. A probe that merely checks the bad
    value is absent from the body passes when the corruption never applied,
    which is the same vacuous pass an unapplied mutation gives: the seam moves,
    the writer is never called, and the test keeps reporting success while
    proving nothing. So the writer records that it ran, and the only non-raising
    outcome allowed is the 500 a served deployment would return.
    """
    from fastapi.exceptions import ResponseValidationError

    from api.v1.endpoints import ai

    original = ai._build_response
    called   = []

    def _corrupt(*args, **kwargs):
        called.append(True)
        return corrupt(original(*args, **kwargs))

    monkeypatch.setattr(ai, "_build_response", _corrupt)
    await _clear_prompt_cache()

    try:
        served = await client.post("/v1/ai/request",
                                   json={"input": f"contract rejection {_unique()}"},
                                   headers=headers)
    except ResponseValidationError as rejected:
        assert expect_named in str(rejected), (
            f"validation rejected the body, but not for {expect_named}: {rejected}"
        )
        return

    assert called, (
        "the scan writer was never called, so nothing was corrupted and this "
        "test proved nothing -- the patched seam is no longer the one the route "
        "builds its body with"
    )
    assert served.status_code == 500, (
        f"the corrupted body was served with {served.status_code}, so the "
        f"response model is not validating this route: {served.text[:200]}"
    )


@pytest.mark.asyncio
async def test_a_fresh_scan_will_not_serve_a_wrong_typed_risk_score(
    client, live_key_headers, monkeypatch,
):
    """`risk_score` is a float the caller may threshold on. A string that is not
    a number cannot be coerced, so a writer emitting one must fail rather than
    serve a body whose most load-bearing field is unusable."""
    def _corrupt(body):
        body["risk_score"] = "high"
        return body

    await _scan_rejects(client, live_key_headers, _corrupt, "risk_score", monkeypatch)


@pytest.mark.asyncio
async def test_a_fresh_scan_will_not_serve_a_body_missing_a_required_field(
    client, live_key_headers, monkeypatch,
):
    """The class no probe in this suite covered: a field REMOVED rather than
    added or retyped.

    It matters more than it looks. Responses are served with unset fields
    excluded, so absence is a normal, meaningful outcome for an optional field --
    which is exactly why a required field going missing has to be the loud case.
    If it were not, the two would be indistinguishable on the wire and a dropped
    field would read to a caller as an optional one that simply did not apply.
    """
    def _corrupt(body):
        body.pop("decision")
        return body

    await _scan_rejects(client, live_key_headers, _corrupt, "decision", monkeypatch)


@pytest.mark.asyncio
async def test_a_fresh_scan_will_not_serve_an_invalid_nested_assessment(
    client, live_key_headers, monkeypatch,
):
    """Nested models are only enforced if validation recurses. `assessment` is a
    model, not a scalar, so replacing it with a string is rejected only when the
    nested shape is checked rather than the top-level keys."""
    def _corrupt(body):
        body["assessment"] = "not-an-object"
        return body

    await _scan_rejects(client, live_key_headers, _corrupt, "assessment", monkeypatch)
