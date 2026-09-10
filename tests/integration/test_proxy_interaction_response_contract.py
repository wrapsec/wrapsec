# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The proxy interaction read-back models are applied by the runtime.

`_serialize` builds both bodies -- the list item and the detail item -- so it is
the injection point for both routes, and each route gets its own detector.

WHY THIS ROUTE'S MODEL MATTERS MORE THAN MOST. The detail body carries
`input_raw` and `output_raw`: the prompt and the provider's reply, as persisted.
The model exists to describe that, never to widen it, so two properties are
asserted directly rather than inferred:

  * the LIST projection must not gain the raw fields. They are modelled on a
    subclass used only by the detail route, so the list schema cannot even
    mention them;
  * the detail body must carry exactly the writer's field set -- a model that
    declared one field more would advertise stored text that this endpoint does
    not return.

Scoping is NOT re-tested here. `test_api_proxy_interactions.py` already covers
own-key-only listing, cross-key 404, system-record 404, admin tenant scope,
cross-tenant isolation and survival of a deleted key; all of it still passes
unchanged, which is the evidence that authorization was untouched.
"""

import hashlib
import uuid

import pytest

from services.time import utc_now

_LEAK = "undeclared_internal_field"


@pytest.fixture
def leaky_serialize(monkeypatch):
    """Emit a field no model declares, from the helper that builds both bodies."""
    from api.v1.endpoints import proxy_interactions

    original = proxy_interactions._serialize

    def _leaky(item, detail=False):
        body = original(item, detail=detail)
        body[_LEAK] = "must not reach the caller"
        return body

    monkeypatch.setattr(proxy_interactions, "_serialize", _leaky)
    return _leaky


@pytest.fixture
async def owned_interaction(test_db):
    """A live key and one interaction it owns. Returns (headers, trace_id)."""
    from db.models import APIKeyModel, DepartmentModel, ProxyInteractionModel
    from db.repositories.tenant import TenantRepository

    tenant = await TenantRepository(test_db).get_bootstrap_default()
    assert tenant is not None

    dept_id = uuid.uuid4()
    test_db.add(DepartmentModel(
        id=dept_id, tenant_id=tenant.id, slug=f"pc-{dept_id.hex[:8]}",
        name="Proxy contract dept", is_active=True,
    ))
    await test_db.flush()

    key_id = "key_" + uuid.uuid4().hex[:8]
    raw    = "wsk_live_" + uuid.uuid4().hex
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id=key_id, tenant_id=tenant.id, dept_id=dept_id,
        app_id=None, name="proxy-contract",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
    ))
    trace_id = "tr-" + uuid.uuid4().hex[:12]
    test_db.add(ProxyInteractionModel(
        id=uuid.uuid4(), trace_id=trace_id, tenant_id=tenant.id, dept_id=dept_id,
        key_id=f"key:{key_id}",           # stored with the prefix the middleware sets
        input_decision="ALLOW", input_primary_reason="NO_THREAT_DETECTED",
        input_confidence=1.0, input_threats=[], execution_status="completed",
        provider="openai", model="gpt-4o", provider_latency_ms=100,
        total_latency_ms=120, output_decision="ALLOW", output_threats=[],
        input_raw="the prompt", output_raw="the reply", created_at=utc_now(),
    ))
    await test_db.commit()
    return {"x-api-key": raw}, trace_id


# ── GET /v1/proxy/interactions ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_the_list_drops_an_undeclared_field(client, owned_interaction, leaky_serialize):
    headers, _ = owned_interaction

    r = await client.get("/v1/proxy/interactions", headers=headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"], "no interactions came back, so nothing was filtered"
    for item in body["items"]:
        assert _LEAK not in item, (
            "an undeclared field reached the caller: the response model is not "
            "being applied, so the success path is returning a Response object"
        )
    assert set(body) == {"total", "limit", "offset", "items"}


@pytest.mark.asyncio
async def test_the_list_never_carries_stored_text(client, owned_interaction):
    """The security property the base/subclass split exists for. A listing must
    not return prompts or replies, and the list schema must not suggest it
    might."""
    from api.v1.schemas.response import ProxyInteraction

    headers, _ = owned_interaction

    r = await client.get("/v1/proxy/interactions", headers=headers)

    assert r.status_code == 200, r.text
    item = r.json()["items"][0]
    for field in ("input_raw", "output_raw", "input_sanitized", "output_sanitized"):
        assert field not in item, f"{field} was returned from a listing"
        assert field not in ProxyInteraction.model_fields, (
            f"{field} is declared on the LIST model, so the schema advertises "
            "stored text that this route does not return"
        )
    assert set(item) == set(ProxyInteraction.model_fields)


@pytest.mark.asyncio
async def test_the_list_echoes_the_clamped_pagination(client, owned_interaction):
    """`limit` and `offset` are clamped by the handler, and the values echoed
    back are the ones actually applied."""
    headers, _ = owned_interaction

    r = await client.get("/v1/proxy/interactions?limit=9999&offset=-5", headers=headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["limit"] == 200 and body["offset"] == 0
    assert isinstance(body["total"], int)


# ── GET /v1/proxy/interactions/{trace_id} ────────────────────────────────────

@pytest.mark.asyncio
async def test_the_detail_drops_an_undeclared_field(client, owned_interaction, leaky_serialize):
    headers, trace_id = owned_interaction

    r = await client.get(f"/v1/proxy/interactions/{trace_id}", headers=headers)

    assert r.status_code == 200, r.text
    assert _LEAK not in r.json(), (
        "an undeclared field reached the caller from the detail route"
    )


@pytest.mark.asyncio
async def test_the_detail_carries_exactly_the_writers_fields(client, owned_interaction):
    from api.v1.schemas.response import ProxyInteractionDetail

    headers, trace_id = owned_interaction

    r = await client.get(f"/v1/proxy/interactions/{trace_id}", headers=headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == set(ProxyInteractionDetail.model_fields), (
        "the served detail and the declared model disagree about the field set"
    )
    assert body["input_raw"] == "the prompt" and body["output_raw"] == "the reply"
    assert body["key_id"] and not body["key_id"].startswith("key:"), (
        "the internal principal prefix must stay internal"
    )


@pytest.mark.asyncio
async def test_the_detail_keeps_empty_fields_null(client, owned_interaction):
    headers, trace_id = owned_interaction

    r = await client.get(f"/v1/proxy/interactions/{trace_id}", headers=headers)

    assert r.status_code == 200, r.text
    body = r.json()
    for field in ("user_id", "input_attack_type", "output_primary_reason",
                  "output_confidence", "behavior_flag", "output_flags",
                  "input_sanitized", "output_sanitized"):
        assert field in body, f"{field} was dropped instead of being null"
        assert body[field] is None


# ── the errors this route actually returns ───────────────────────────────────

# The reduced body this route used to return, kept as data so the regression
# tests below state the old shape once instead of describing it in prose. A body
# matching this exactly is the defect, not merely a different field set.
_REDUCED_404 = {"code", "message"}


@pytest.mark.asyncio
async def test_a_missing_interaction_returns_the_catalog_envelope(client, owned_interaction):
    """CONVERTED. This 404 used to be a reduced body -- `code` and `message` only.

    It is now the catalog envelope every other WrapSec error uses, which is what
    the schema advertises. The status and the error code are unchanged; what a
    caller gains is `severity`, `key`, `params` and a `trace_id` to correlate on.

    The field set is asserted exactly, in both directions: a missing field is a
    reduced envelope creeping back, and an extra one is an undeclared field on an
    error body. `invalid_params` is absent because a lookup miss has no per-field
    detail -- the builder omits it rather than sending an empty list.
    """
    headers, _ = owned_interaction

    r = await client.get(f"/v1/proxy/interactions/tr-{uuid.uuid4().hex[:12]}", headers=headers)

    assert r.status_code == 404
    body = r.json()
    assert set(body) == {"error"}

    error = body["error"]
    assert set(error) == {"code", "severity", "key", "params", "message", "trace_id"}, (
        f"the 404 envelope changed: {sorted(error)}"
    )
    assert set(error) != _REDUCED_404, "the reduced 404 envelope is back"
    assert error["code"]     == "NOT_FOUND"
    assert error["severity"] == "WARNING"
    assert error["key"]      == "errors.NOT_FOUND"
    assert error["params"]   == {"resource": "interaction"}
    assert error["trace_id"].startswith("req_")


@pytest.mark.asyncio
async def test_the_404_does_not_echo_the_requested_trace_id(client, owned_interaction):
    """The identifier stays out of the body, which is a tightening, not a loss.

    The old message interpolated the caller's own path segment
    (`Interaction <trace_id> not found.`). The catalog resolves the message from
    `params.resource` alone, and the identifier travels in `debug_message`, which
    is logged and never serialized -- the same treatment
    `GET /v1/ai/requests/{trace_id}` already gives an identical lookup.

    Asserted with a value that would be unmistakable if it were reflected, so
    this also covers the general case of caller input reaching an error body.
    """
    headers, _ = owned_interaction
    probe = "tr-reflect-me-b06f1d0a"

    r = await client.get(f"/v1/proxy/interactions/{probe}", headers=headers)

    assert r.status_code == 404
    assert probe not in r.text, "the requested trace_id is reflected into the 404 body"
    assert r.json()["error"]["message"] == "interaction not found."


@pytest.mark.asyncio
async def test_out_of_scope_and_absent_are_the_same_404(client, owned_interaction, test_db):
    """The security property the three 404 branches exist to hold.

    An interaction that EXISTS but belongs to another key must be indistinguishable
    from one that does not exist -- otherwise the 404 becomes an oracle for probing
    which trace_ids are real. Converting the body to the catalog envelope must not
    weaken that, so the two responses are compared field by field with only
    `trace_id` (per-request by definition) allowed to differ.
    """
    import uuid as _uuid

    from db.models import ProxyInteractionModel

    headers, _ = owned_interaction

    foreign = "tr-" + _uuid.uuid4().hex[:12]
    test_db.add(ProxyInteractionModel(
        id=_uuid.uuid4(), trace_id=foreign, key_id="key:someone_else",
        input_decision="ALLOW", input_primary_reason="NO_THREAT_DETECTED",
        input_confidence=1.0, input_threats=[], execution_status="completed",
        provider="openai", model="gpt-4o", provider_latency_ms=1,
        total_latency_ms=2, output_decision="ALLOW", output_threats=[],
        created_at=utc_now(),
    ))
    await test_db.commit()

    exists_elsewhere = await client.get(f"/v1/proxy/interactions/{foreign}", headers=headers)
    absent = await client.get(
        f"/v1/proxy/interactions/tr-{_uuid.uuid4().hex[:12]}", headers=headers)

    assert exists_elsewhere.status_code == absent.status_code == 404
    a = {k: v for k, v in exists_elsewhere.json()["error"].items() if k != "trace_id"}
    b = {k: v for k, v in absent.json()["error"].items() if k != "trace_id"}
    assert a == b, f"the 404 distinguishes out-of-scope from absent: {a} vs {b}"


@pytest.mark.asyncio
async def test_the_404_carries_no_interaction_data(client, owned_interaction, test_db):
    """Converting to a richer envelope must not enrich it with the wrong things.

    The envelope gained `params`, which is the one field a call site controls. It
    carries the resource NAME only -- so none of the foreign interaction's stored
    values, nor the owning key, may appear anywhere in the 404 body.
    """
    import uuid as _uuid

    from db.models import ProxyInteractionModel

    headers, _ = owned_interaction

    secret_model = "gpt-secret-deployment-a41c"
    foreign      = "tr-" + _uuid.uuid4().hex[:12]
    test_db.add(ProxyInteractionModel(
        id=_uuid.uuid4(), trace_id=foreign, key_id="key:another_tenants_key",
        input_decision="BLOCK", input_primary_reason="RULE_DETECTOR",
        input_confidence=1.0, input_threats=["PROMPT_INJECTION"],
        execution_status="completed", provider="openai", model=secret_model,
        provider_latency_ms=1, total_latency_ms=2, output_decision="ALLOW",
        output_threats=[], input_raw="the other tenant's prompt",
        output_raw="the other tenant's reply", created_at=utc_now(),
    ))
    await test_db.commit()

    r = await client.get(f"/v1/proxy/interactions/{foreign}", headers=headers)

    assert r.status_code == 404
    for leaked in (secret_model, "another_tenants_key", "the other tenant's prompt",
                   "the other tenant's reply", "PROMPT_INJECTION", "RULE_DETECTOR"):
        assert leaked not in r.text, f"the 404 body carried {leaked!r}"
    assert r.json()["error"]["params"] == {"resource": "interaction"}


@pytest.mark.asyncio
async def test_an_unparseable_limit_returns_the_catalog_envelope(client, owned_interaction):
    """The 422 the list route declares. It is the catalog envelope at runtime,
    which is why the generated HTTPValidationError schema was replaced."""
    headers, _ = owned_interaction

    r = await client.get("/v1/proxy/interactions?limit=not-a-number", headers=headers)

    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert r.json()["error"]["invalid_params"][0]["field"] == "limit"


# ── the list refuses an item the model cannot accept ─────────────────────────

@pytest.mark.asyncio
async def test_the_list_will_not_serve_a_wrong_typed_item(
    client, owned_interaction, monkeypatch,
):
    """This family had no rejection probe either -- both existing tests prove
    filtering.

    `_serialize` builds BOTH bodies, so corrupting it here exercises the list;
    the detail route shares the helper and the same model inheritance, which is
    what carries the declaration to it.
    """
    from fastapi.exceptions import ResponseValidationError

    from api.v1.endpoints import proxy_interactions

    original = proxy_interactions._serialize

    called = []

    def _corrupt(item, detail=False):
        called.append(True)
        body = original(item, detail=detail)
        body["total_latency_ms"] = "ages"
        return body

    monkeypatch.setattr(proxy_interactions, "_serialize", _corrupt)

    headers, _ = owned_interaction

    try:
        r = await client.get("/v1/proxy/interactions", headers=headers)
    except ResponseValidationError as rejected:
        assert "total_latency_ms" in str(rejected), (
            f"validation rejected the listing, but not for total_latency_ms: {rejected}"
        )
        return

    # A clean 200 is not evidence: it is what an unapplied corruption also
    # produces. See the note on the same shape in the scan family.
    assert called, (
        "`_serialize` was never called, so no item was corrupted and this test "
        "proved nothing about validation"
    )
    assert r.status_code == 500, (
        f"an item violating the declared type was served with {r.status_code}, "
        "so the response model is not validating this route"
    )


# ── why this family has no runtime vocabulary check ──────────────────────────
#
# The other two families assert that a real body only carries values the schema
# publishes. This one deliberately does not, and the reason is worth stating so
# nobody adds it later.
#
# These bodies are STORED ROWS, not values a writer just produced. The fixtures
# here seed `execution_status="completed"` -- a value production never writes
# and the published vocabulary does not contain -- and
# `test_the_proxy_interaction_runtime_still_accepts_an_unknown_value` asserts it
# must still round-trip, because the schema documents the vocabulary and does
# not enforce it. A historical row holding a retired value has to keep reading
# back rather than turning into a 500.
#
# So a runtime check here would assert the fixture, and would contradict that
# position the moment it passed. The writer side is guarded instead, in
# `tests/unit/test_proxy_status_vocabulary.py`: the constants this family's
# producer can emit must all be published values. That is the half Option C
# actually needs -- what the API EMITS is closed, what it ACCEPTS on read-back
# stays open.
