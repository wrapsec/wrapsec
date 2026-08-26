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

@pytest.mark.asyncio
async def test_a_missing_interaction_keeps_its_existing_404_body(client, owned_interaction):
    """PINNED, NOT ENDORSED. This 404 is a reduced body -- `code` and `message`
    only -- not the catalog envelope every other WrapSec error uses. This pass
    preserves error behaviour, so the shape is recorded here rather than changed,
    and the schema does not advertise ErrorEnvelope for it. Fixing it is an
    error-contract change and will fail this test deliberately."""
    headers, _ = owned_interaction

    r = await client.get(f"/v1/proxy/interactions/tr-{uuid.uuid4().hex[:12]}", headers=headers)

    assert r.status_code == 404
    body = r.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message"}, (
        f"the 404 body changed: {sorted(body['error'])}. If it now carries the "
        "catalog envelope, that is an error-contract change -- update this test."
    )
    assert body["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_an_unparseable_limit_returns_the_catalog_envelope(client, owned_interaction):
    """The 422 the list route declares. It is the catalog envelope at runtime,
    which is why the generated HTTPValidationError schema was replaced."""
    headers, _ = owned_interaction

    r = await client.get("/v1/proxy/interactions?limit=not-a-number", headers=headers)

    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert r.json()["error"]["invalid_params"][0]["field"] == "limit"
