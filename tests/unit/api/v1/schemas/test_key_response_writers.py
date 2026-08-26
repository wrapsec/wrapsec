# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The public key writers cannot produce a body the models reject -- and cannot
smuggle a credential into a listing.

Both handlers assemble their body inline, so this file mirrors those dicts field
for field from a row, rather than importing a formatter that does not exist. What
it establishes:

  * every REQUIRED field maps to a NOT NULL column or to a value the handler
    generates: `key_id`, `name`, `key_type`, `created_at` and, on creation,
    `api_key` and the request's own `name`. `tenant_id` is NOT NULL in the table,
    though the writer still emits it defensively as `str(x) if x else None`, so
    the model follows the writer and allows null;
  * the ONE writer fallback on this surface -- `getattr(k, "key_type", "live") or
    "live"` -- is what lets `key_type` be required in the list model, and it is
    exercised rather than assumed;
  * neither model can carry credential material. Feeding a poisoned body through
    them drops `api_key`, `key_hash` and the internal flags.

LEGACY ROWS. Five migrations touch `api_keys`: `0010_timestamptz` (type change),
`0022_api_key_ip_allowlist` and `0024_ip_allowlist_jsonb` (a NULLABLE column, and
one this projection never returns), and `0019` / `0023`, which target other
tables. No field either response returns was added after the table was created,
so no supported row predates one.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from api.v1.schemas.response import (
    ApiKeyCreated,
    ApiKeyListItem,
    ApiKeyListResponse,
)
from services.time import to_iso_z, utc_now


def _row(**overrides) -> SimpleNamespace:
    """An api_keys row with every NULLABLE column null."""
    base = {
        "id": uuid.uuid4(), "key_id": "key_abc123", "name": "a key",
        "tenant_id": uuid.uuid4(), "dept_id": None, "app_id": None,
        "key_hash": "sha256:secret", "key_type": "live", "is_admin": False,
        "revoked": False, "expires_at": None, "last_used_at": None,
        "created_at": utc_now(), "ip_allowlist": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _list_item(row, dept_names=None, app_names=None) -> dict:
    """The dict the listing handler builds, mirrored branch for branch."""
    dept_names = dept_names or {}
    app_names  = app_names or {}
    return {
        "key_id":       row.key_id,
        "name":         row.name,
        "app_id":       str(row.app_id)  if row.app_id  else None,
        "dept_id":      str(row.dept_id) if row.dept_id else None,
        "dept_name":    dept_names.get(str(row.dept_id)) if row.dept_id else None,
        "app_name":     app_names.get(str(row.app_id))   if row.app_id  else None,
        "key_type":     getattr(row, "key_type", "live") or "live",
        "created_at":   to_iso_z(row.created_at),
        "expires_at":   to_iso_z(row.expires_at) if row.expires_at else None,
        "last_used_at": to_iso_z(row.last_used_at) if row.last_used_at else None,
    }


def _created_body(row, *, api_key="wsk_live_" + "a" * 32) -> dict:
    """The dict the creation handler builds."""
    return {
        "key_id":     row.key_id,
        "name":       row.name,
        "api_key":    api_key,
        "key_type":   row.key_type,
        "app_id":     str(row.app_id)    if row.app_id    else None,
        "dept_id":    str(row.dept_id)   if row.dept_id   else None,
        "tenant_id":  str(row.tenant_id) if row.tenant_id else None,
        "created_at": to_iso_z(row.created_at),
        "expires_at": to_iso_z(row.expires_at) if row.expires_at else None,
    }


_ROWS = {
    "emptiest_row":   {},
    "trial_key":      {"key_type": "trial"},
    "dept_scoped":    {"dept_id": uuid.uuid4()},
    "app_scoped":     {"dept_id": uuid.uuid4(), "app_id": uuid.uuid4()},
    "expiring":       {"expires_at": utc_now()},
    "used_before":    {"last_used_at": utc_now()},
    "allowlisted":    {"ip_allowlist": ["10.0.0.0/8"]},
}


@pytest.mark.parametrize("name", sorted(_ROWS))
def test_every_list_body_the_writer_produces_satisfies_the_model(name):
    item   = _list_item(_row(**_ROWS[name]))
    served = ApiKeyListItem.model_validate(item).model_dump(exclude_unset=True)

    assert set(served) == set(item), (
        f"{name}: the model changed the key set "
        f"(dropped {set(item) - set(served)}, added {set(served) - set(item)})"
    )
    assert served == item, f"{name}: the model altered a value"
    ApiKeyListResponse.model_validate({"keys": [item]})


@pytest.mark.parametrize("name", sorted(_ROWS))
def test_every_creation_body_the_writer_produces_satisfies_the_model(name):
    body   = _created_body(_row(**_ROWS[name]))
    served = ApiKeyCreated.model_validate(body).model_dump(exclude_unset=True)

    assert set(served) == set(body)
    assert served == body


def test_the_key_type_fallback_is_what_keeps_the_field_non_null():
    """`key_type` is NOT NULL with a default in the table, and the writer still
    guards it with `or "live"`. That guard is why the model can require it."""
    assert _list_item(_row(key_type=None))["key_type"] == "live"
    assert _list_item(_row(key_type=""))["key_type"] == "live"
    ApiKeyListItem.model_validate(_list_item(_row(key_type=None)))


def test_an_empty_listing_is_a_list_not_a_null():
    served = ApiKeyListResponse.model_validate({"keys": []}).model_dump(exclude_unset=True)
    assert served == {"keys": []}


# ── neither model can carry credential material ──────────────────────────────

@pytest.mark.parametrize("model", [ApiKeyListItem, ApiKeyCreated])
def test_no_model_declares_stored_credential_material(model):
    for field in ("key_hash", "is_admin", "revoked", "ip_allowlist", "id"):
        assert field not in model.model_fields, (
            f"{model.__name__} declares {field}, so the schema advertises "
            "internal credential material"
        )


def test_the_list_model_has_no_field_that_could_hold_a_secret():
    assert "api_key" not in ApiKeyListItem.model_fields
    poisoned = {**_list_item(_row()), "api_key": "wsk_live_LEAKED", "key_hash": "x"}

    served = ApiKeyListItem.model_validate(poisoned).model_dump(exclude_unset=True)

    assert "api_key" not in served and "key_hash" not in served
    assert "wsk_live_LEAKED" not in str(served)


def test_the_creation_model_carries_the_secret_and_only_the_secret():
    """The one place a credential is contractual. It must be there, and the
    surrounding fields must still be metadata."""
    assert "api_key" in ApiKeyCreated.model_fields
    body   = _created_body(_row())
    served = ApiKeyCreated.model_validate(body).model_dump(exclude_unset=True)

    assert served["api_key"] == body["api_key"]
    assert set(served) - {"api_key"} == set(body) - {"api_key"}
