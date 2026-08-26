# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The audit-item writer cannot produce an item the model rejects.

`_format_item` feeds TWO published routes -- `GET /v1/audit/logs` (as `items`)
and `GET /v1/agent-runs/{run_id}` (as `turns`) -- through the single `AuditItem`
model, so this premise covers both.

Response validation is fail-closed, so the model is only a safe boundary while
the writer behind it cannot emit a violating shape. The writer here is
`_format_item` in the audit endpoints, reading an `audit_logs` row plus the
batch-resolved department, application and proxy lookups.

The rows exercised below are the widest the schema permits: every NULLABLE column
actually null. What keeps that valid is which columns are NOT nullable --
`trace_id`, `decision`, `risk_score`, `threats`, `input_hash`, `detection_mode`,
`execution_mode`, `latency_ms`, `attribution_verified`, `created_at` and
`input_source` -- and three fallbacks in the writer itself: `severity` is
computed when the column is null, `input_length or 0`, and `threats or []`.

`input_source` is the one that is not obvious from the model definition. It was
added in `0011_audit_input_source` as `nullable=False, server_default="user_prompt"`,
so rows written before it exists carry the default rather than null.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from api.v1.endpoints.audit import _format_item
from api.v1.schemas.response import AuditItem
from services.time import utc_now


def _row(**overrides) -> SimpleNamespace:
    """An audit row with every nullable column null -- the emptiest row the
    schema allows."""
    base = {
        "trace_id": "req_x", "created_at": utc_now(), "tenant_id": None,
        "decision": "ALLOW", "primary_reason": None, "risk_score": 0.0,
        "confidence": None, "confidence_band": None, "threats": None,
        "input_hash": "sha256:abc", "detection_mode": "fast",
        "execution_mode": "scan_only", "latency_ms": 1.0, "key_id": None,
        "dept_id": None, "app_id": None, "user_id": None, "source": None,
        "ip_address": None, "attribution_verified": False, "policy_source": None,
        "input_length": None, "severity": None, "session_id": None,
        "turn_index": None, "run_id": None, "input_source": "user_prompt",
        "record_hash": None, "prev_hash": None, "proxy_interaction_id": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


_PROXY = SimpleNamespace(output_decision="ALLOW", provider="openai", model="gpt-4o")

_VARIANTS = {
    "emptiest_row":      ({}, {}, {}, {}),
    "severity_stored":   ({"severity": "WARNING"}, {}, {}, {}),
    "no_input_length":   ({"input_length": None}, {}, {}, {}),
    "threats_present":   ({"threats": ["PROMPT_INJECTION"]}, {}, {}, {}),
    "named_scope":       ({"dept_id": "d1", "app_id": "a1"},
                          {"d1": "Engineering"}, {"a1": "Checkout"}, {}),
    "unresolved_names":  ({"dept_id": "gone", "app_id": "gone"}, {}, {}, {}),
    "agentic_fields":    ({"run_id": "run-1", "session_id": "sess-1", "turn_index": 3}, {}, {}, {}),
    "chained_row":       ({"record_hash": "a" * 64, "prev_hash": "b" * 64}, {}, {}, {}),
}


@pytest.mark.parametrize("name", sorted(_VARIANTS))
def test_every_turn_the_writer_produces_satisfies_the_model(name):
    overrides, depts, apps, proxies = _VARIANTS[name]
    turn = _format_item(_row(**overrides), depts, apps, proxies)

    served = AuditItem.model_validate(turn).model_dump(exclude_unset=True)

    assert set(served) == set(turn), (
        f"{name}: the model changed the key set "
        f"(dropped {set(turn) - set(served)}, added {set(served) - set(turn)})"
    )
    assert served == turn, f"{name}: the model altered a value"


def test_a_proxy_turn_satisfies_the_model():
    """The enriched branch: three fields that are null on every scan-only turn
    carry values here."""
    pid  = "11111111-1111-1111-1111-111111111111"
    turn = _format_item(
        _row(proxy_interaction_id=pid, execution_mode="proxy"), {}, {}, {pid: _PROXY},
    )

    served = AuditItem.model_validate(turn).model_dump(exclude_unset=True)
    assert served["output_decision"] == "ALLOW"
    assert served["provider"] == "openai" and served["model"] == "gpt-4o"


def test_the_writer_fallbacks_are_what_keep_the_required_fields_non_null():
    """Three fields are required in the model but nullable in the database. The
    writer, not the schema, is what makes them safe -- asserted here so a change
    to either side fails rather than producing a 500 at read-back."""
    turn = _format_item(_row(severity=None, input_length=None, threats=None), {}, {}, {})

    assert isinstance(turn["severity"], str), "severity fell through as null"
    assert turn["input_length"] == 0, "input_length fell through as null"
    assert turn["threats"] == [], "threats fell through as null"
    AuditItem.model_validate(turn)


def test_the_model_declares_exactly_the_writers_fields():
    """Pins the projection at the writer. A field added to `_format_item` and not
    to the model would be dropped by the response filter, silently."""
    turn = _format_item(_row(), {}, {}, {})

    assert set(turn) == set(AuditItem.model_fields), (
        f"writer and model disagree (writer only: {set(turn) - set(AuditItem.model_fields)}, "
        f"model only: {set(AuditItem.model_fields) - set(turn)})"
    )
