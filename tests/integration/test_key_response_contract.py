# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The public key routes' response models are applied by the runtime.

`POST /v1/keys` returns the one body in this API that carries a credential, and
`GET /v1/keys` must never carry one. Both used to answer with a constructed
`JSONResponse`, which skips the model entirely -- so a field added anywhere in
those handlers reached the caller unfiltered. These tests run over real HTTP and
fail if either return goes back.

Two writers, two detectors: each handler builds its own body inline, so each is
patched separately and neither test can pass on the other's behalf.

WHAT THE FILTER IS WORTH HERE. The credential is declared on the creation model
alone. The list model has no field that could hold one, so even a writer that
started emitting `api_key` in a listing would have it dropped before
serialization -- which is asserted directly, by injecting exactly that.

Authorization is NOT re-tested here. `test_api_keys.py` already covers ADMIN-only
creation, tenant scope, department scoping for a non-admin reader, and the
exclusion of revoked and expired keys; all of it still passes, which is the
evidence that nothing in this pass touched it.
"""

import uuid

import pytest

_LEAK = "undeclared_internal_field"


@pytest.fixture
async def admin_dept(test_db, admin_jwt_headers):
    """A department in the admin's tenant, required to create a key."""
    from db.models import DepartmentModel
    from services.auth.token import decode_access_token

    payload   = decode_access_token(admin_jwt_headers["Authorization"].split()[1])
    tenant_id = uuid.UUID(payload["tenant_id"])
    dept_id   = uuid.uuid4()
    test_db.add(DepartmentModel(
        id=dept_id, tenant_id=tenant_id, slug=f"kc-{dept_id.hex[:6]}",
        name="Key contract dept", is_active=True,
    ))
    await test_db.commit()
    return str(dept_id)


async def _create(client, headers, dept_id, **extra):
    payload = {"name": f"contract key {uuid.uuid4().hex[:6]}", "dept_id": dept_id}
    payload.update(extra)
    return await client.post("/v1/keys", json=payload, headers=headers)


# ── POST /v1/keys ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_creation_will_not_serve_a_wrong_typed_timestamp(
    client, admin_jwt_headers, admin_dept, monkeypatch,
):
    """Both key handlers assemble their body inline, so there is no shared
    formatter to wrap and no way to inject an undeclared KEY. The equivalent
    proof is a type violation at the one value the handler takes from a
    module-level helper: `created_at` comes from `to_iso_z`. Forced to an int,
    the model must refuse -- a `JSONResponse` would serve the integer where the
    contract says timestamp, which is exactly the reverted state.
    """
    from fastapi.exceptions import ResponseValidationError

    from api.v1.endpoints import keys as keys_module

    monkeypatch.setattr(keys_module, "to_iso_z", lambda *_a, **_k: 12345)

    try:
        r = await _create(client, admin_jwt_headers, admin_dept)
    except ResponseValidationError as rejected:
        assert "created_at" in str(rejected)
        return

    assert r.status_code not in (200, 201) or "12345" not in r.text, (
        "a timestamp violating the declared type was served, so the response "
        "model is not applied to key creation"
    )


@pytest.mark.asyncio
async def test_creation_returns_the_secret_exactly_once(client, admin_jwt_headers, admin_dept):
    """The credential is the reason this route exists. It must be present at
    creation, be a usable key, and never appear again in a listing."""
    r = await _create(client, admin_jwt_headers, admin_dept)

    assert r.status_code == 201, r.text
    body = r.json()
    assert body["api_key"].startswith("wsk_live_"), "the raw key was not returned"
    assert body["key_id"] and not body["key_id"].startswith("wsk_")

    listed = await client.get("/v1/keys", headers=admin_jwt_headers)
    assert listed.status_code == 200, listed.text
    for item in listed.json()["keys"]:
        assert "api_key" not in item, "a credential appeared in a listing"
        assert body["api_key"] not in str(item), "the raw key leaked into a listing"


@pytest.mark.asyncio
async def test_creation_never_returns_stored_credential_material(client, admin_jwt_headers, admin_dept):
    """The row stores a hash and several internal flags. None of them is part of
    the response, and the model declares none of them."""
    from api.v1.schemas.response import ApiKeyCreated

    r = await _create(client, admin_jwt_headers, admin_dept)

    assert r.status_code == 201, r.text
    for field in ("key_hash", "is_admin", "revoked", "ip_allowlist", "id"):
        assert field not in r.json(), f"{field} reached the caller"
        assert field not in ApiKeyCreated.model_fields, (
            f"{field} is declared on the creation model, so the schema advertises "
            "internal credential material"
        )


# ── GET /v1/keys ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_the_listing_will_not_serve_a_wrong_typed_timestamp(
    client, admin_jwt_headers, admin_dept, monkeypatch,
):
    """The listing's own detector, same instrument, its own success return."""
    from fastapi.exceptions import ResponseValidationError

    from api.v1.endpoints import keys as keys_module

    created = await _create(client, admin_jwt_headers, admin_dept)
    assert created.status_code == 201, created.text

    monkeypatch.setattr(keys_module, "to_iso_z", lambda *_a, **_k: 12345)

    try:
        r = await client.get("/v1/keys", headers=admin_jwt_headers)
    except ResponseValidationError as rejected:
        assert "created_at" in str(rejected)
        return

    assert r.status_code != 200 or "12345" not in r.text, (
        "a timestamp violating the declared type was served from the listing"
    )


@pytest.mark.asyncio
async def test_a_credential_added_to_a_list_item_is_filtered_out(client, admin_jwt_headers, admin_dept):
    """The property the two-model split exists for, tested rather than asserted
    as a convention: even if a writer started putting `api_key` into a list item,
    the model has no field to hold it and the filter drops it before
    serialization. Proven against the real model, then confirmed against the live
    endpoint's body.
    """
    from api.v1.schemas.response import ApiKeyListItem

    created = await _create(client, admin_jwt_headers, admin_dept)
    assert created.status_code == 201, created.text

    r = await client.get("/v1/keys", headers=admin_jwt_headers)
    assert r.status_code == 200, r.text
    item = next(i for i in r.json()["keys"] if i["key_id"] == created.json()["key_id"])

    poisoned = {**item, "api_key": "wsk_live_LEAKED_SECRET", "key_hash": "deadbeef"}
    filtered = ApiKeyListItem.model_validate(poisoned).model_dump(exclude_unset=True)

    assert "api_key" not in filtered and "key_hash" not in filtered, (
        "the list model accepted credential material, so a writer emitting it "
        "would reach the caller"
    )
    assert filtered == item, "filtering changed a legitimate field"
    assert "wsk_live_" not in r.text, "a raw key appeared in the listing response"


@pytest.mark.asyncio
async def test_the_listing_keeps_empty_fields_null(client, admin_jwt_headers, admin_dept):
    live = await _create(client, admin_jwt_headers, admin_dept)
    assert live.status_code == 201, live.text

    r = await client.get("/v1/keys", headers=admin_jwt_headers)

    assert r.status_code == 200, r.text
    item = next(i for i in r.json()["keys"] if i["key_id"] == live.json()["key_id"])
    for field in ("app_id", "app_name", "expires_at", "last_used_at"):
        assert field in item, f"{field} was dropped instead of being null"
        assert item[field] is None
    assert item["dept_id"] == admin_dept and item["dept_name"] == "Key contract dept"


# ── errors ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_an_invalid_key_type_returns_the_catalog_envelope(client, admin_jwt_headers, admin_dept):
    """The 422 the creation route declares."""
    r = await _create(client, admin_jwt_headers, admin_dept, key_type="platinum")

    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_an_api_key_caller_cannot_create_a_key(client, scored_key_pair):
    """Creation is JWT + ADMIN. An API key -- even a live one -- is refused, and
    the refusal shape is unchanged by this pass."""
    live, _ = scored_key_pair

    r = await client.post("/v1/keys", json={"name": "nope"}, headers=live)

    assert r.status_code in (401, 403), r.text
    assert "api_key" not in r.json(), "a refusal must not carry a credential"
