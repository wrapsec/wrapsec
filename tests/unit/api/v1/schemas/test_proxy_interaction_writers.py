# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The proxy interaction writer cannot produce a body the models reject.

`_serialize` is the single writer for both routes, reading a `proxy_interactions`
row. Response validation is fail-closed, so the model is only a safe boundary
while that writer cannot emit a violating shape.

WHAT MAKES THE REQUIRED FIELDS SAFE. Each one maps to a column that is NOT NULL:
`trace_id`, `input_decision`, `input_primary_reason`, `input_confidence`,
`execution_status`, `total_latency_ms`, `created_at`, and the primary key. The two
list-typed fields are nullable in the database and the writer supplies `or []`,
which is asserted below rather than assumed.

LEGACY ROWS. Three migrations have touched this table since it was created --
`0019_proxy_interactions_tenant`, `0021_proxy_scan_latency` and the `0010`
timestamptz conversion. The first two add only NULLABLE columns, and neither adds
a field this projection returns; the third changes a type, not a value. So no
supported row predates a field the model requires, and none can carry a shape it
rejects.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from api.v1.endpoints.proxy_interactions import _serialize
from api.v1.schemas.response import ProxyInteraction, ProxyInteractionDetail
from services.time import utc_now


def _row(**overrides) -> SimpleNamespace:
    """A row with every NULLABLE column null -- the emptiest the schema allows."""
    base = {
        "id": uuid.uuid4(), "trace_id": "tr-x", "created_at": utc_now(),
        "key_id": None, "user_id": None,
        "input_decision": "ALLOW", "input_primary_reason": "NO_THREAT_DETECTED",
        "input_confidence": 1.0, "input_threats": None, "input_attack_type": None,
        "provider": None, "model": None, "provider_latency_ms": None,
        "execution_status": "completed", "output_decision": None,
        "output_primary_reason": None, "output_confidence": None,
        "output_threats": None, "behavior_flag": None, "output_flags": None,
        "total_latency_ms": 0,
        "input_raw": None, "input_sanitized": None,
        "output_raw": None, "output_sanitized": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


_VARIANTS = {
    "emptiest_row":     {},
    "system_record":    {"key_id": None},
    "owned_record":     {"key_id": "key:key_abc123"},
    "provider_called":  {"provider": "openai", "model": "gpt-4o",
                         "provider_latency_ms": 100, "output_decision": "ALLOW",
                         "output_confidence": 0.9},
    "threats_present":  {"input_threats": ["PROMPT_INJECTION"],
                         "output_threats": ["PII"]},
    "flags_present":    {"behavior_flag": "suspicious", "output_flags": {"a": 1}},
    "text_retained":    {"input_raw": "hello", "output_raw": "hi",
                         "input_sanitized": "[REDACTED]", "output_sanitized": "ok"},
}


@pytest.mark.parametrize("name", sorted(_VARIANTS))
def test_every_list_body_the_writer_produces_satisfies_the_model(name):
    body   = _serialize(_row(**_VARIANTS[name]))
    served = ProxyInteraction.model_validate(body).model_dump(exclude_unset=True)

    assert set(served) == set(body), (
        f"{name}: the model changed the key set "
        f"(dropped {set(body) - set(served)}, added {set(served) - set(body)})"
    )
    assert served == body, f"{name}: the model altered a value"


@pytest.mark.parametrize("name", sorted(_VARIANTS))
def test_every_detail_body_the_writer_produces_satisfies_the_model(name):
    body   = _serialize(_row(**_VARIANTS[name]), detail=True)
    served = ProxyInteractionDetail.model_validate(body).model_dump(exclude_unset=True)

    assert set(served) == set(body)
    assert served == body


def test_the_list_projection_is_the_detail_projection_minus_the_stored_text():
    """The exact difference between the two, asserted once so a field cannot be
    added to one without a decision about the other."""
    row  = _row(input_raw="p", output_raw="r")
    only_in_detail = set(_serialize(row, detail=True)) - set(_serialize(row))

    assert only_in_detail == {"input_raw", "input_sanitized", "output_raw", "output_sanitized"}
    assert set(ProxyInteractionDetail.model_fields) - set(ProxyInteraction.model_fields) == only_in_detail


def test_the_writer_fallbacks_keep_the_list_fields_non_null():
    """`input_threats` and `output_threats` are nullable columns but required
    lists in the model. The writer's `or []` is what stands between the two."""
    body = _serialize(_row(input_threats=None, output_threats=None))

    assert body["input_threats"] == [] and body["output_threats"] == []
    ProxyInteraction.model_validate(body)


def test_the_internal_principal_prefix_is_stripped_before_it_leaves():
    """`request.state.key_id` is `key:<id>`; the response returns the bare id.
    A model change must not start passing the internal form through."""
    assert _serialize(_row(key_id="key:key_abc123"))["key_id"] == "key_abc123"
    assert _serialize(_row(key_id=None))["key_id"] is None


def test_the_model_declares_exactly_the_writers_fields():
    row = _row()
    assert set(_serialize(row)) == set(ProxyInteraction.model_fields)
    assert set(_serialize(row, detail=True)) == set(ProxyInteractionDetail.model_fields)
