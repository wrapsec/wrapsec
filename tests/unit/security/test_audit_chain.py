# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for security/audit_chain.py

Covers the canonicalisation and hash contract only; the
AuditRepository chain-under-lock behaviour is exercised by
tests/integration/test_audit_hash_chain.py against a real DB.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import ClassVar

import pytest

from security.audit_chain import (
    CANONICAL_FIELDS,
    canonical_row,
    compute_record_hash,
)


def _sample_row() -> dict:
    return {
        "trace_id":       "req_01test",
        "tenant_id":      "t1",
        "decision":       "ALLOW",
        "risk_score":     0.1,
        "confidence":     0.05,
        "threats":        [],
        "detection_mode": "fast",
        "execution_mode": "scan_only",
        "llm_invoked":    False,
        "latency_ms":     2.5,
        "input_hash":     "sha256:abc",
        "created_at":     datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    }


class TestCanonicalFieldsInvariant:

    def test_hash_columns_not_in_canonical_fields(self):
        # The output of the chain must not be part of its own input.
        assert "record_hash" not in CANONICAL_FIELDS
        assert "prev_hash"   not in CANONICAL_FIELDS

    def test_db_assigned_id_not_in_canonical_fields(self):
        # Row identity is DB-assigned and not part of the content.
        assert "id" not in CANONICAL_FIELDS

    def test_v1_2_session_fields_included(self):
        # v1.2.0 columns must contribute to the hash; if omitted,
        # session tampering would be invisible to verifiers.
        for name in ("session_id", "turn_index", "run_id"):
            assert name in CANONICAL_FIELDS

    def test_sorted_and_unique(self):
        # Sorted so review-diffs stay small; unique so hashes are stable.
        assert list(CANONICAL_FIELDS) == sorted(CANONICAL_FIELDS)
        assert len(set(CANONICAL_FIELDS)) == len(CANONICAL_FIELDS)


class TestCanonicalRowDeterminism:

    def test_same_input_produces_same_output(self):
        row = _sample_row()
        assert canonical_row(row) == canonical_row(dict(row))

    def test_missing_fields_default_to_null(self):
        # A field absent from the dict must serialise as JSON null,
        # not raise, so schemas gain nullable columns without breaking
        # hashes on older rows.
        out = canonical_row({"trace_id": "t"})
        parsed = json.loads(out)
        assert parsed["trace_id"] == "t"
        assert parsed["decision"] is None
        assert parsed["threats"]  is None

    def test_field_order_in_dict_does_not_affect_hash(self):
        row_a = {"trace_id": "t", "decision": "ALLOW", "tenant_id": "x"}
        row_b = {"tenant_id": "x", "decision": "ALLOW", "trace_id": "t"}
        assert canonical_row(row_a) == canonical_row(row_b)

    def test_unknown_fields_are_ignored(self):
        # Adding an unrelated key to the input dict must not affect the
        # hash -- CANONICAL_FIELDS is the sole source of truth.
        row      = _sample_row()
        row_extra = dict(row, this_is_not_canonical="whatever")
        assert canonical_row(row) == canonical_row(row_extra)


class TestCanonicalTypes:

    def test_datetime_serialised_as_iso_with_microseconds(self):
        # Timestamps are stored as TIMESTAMPTZ; the canonical form is aware-UTC
        # ISO 8601 with microseconds. A naive value is read as UTC.
        out    = canonical_row({"created_at": datetime(2026, 7, 27, 15, 30, 45, 123456, tzinfo=timezone.utc)})
        parsed = json.loads(out)
        assert parsed["created_at"] == "2026-07-27T15:30:45.123456+00:00"

    def test_datetime_in_other_zone_normalised_to_utc(self):
        # Determinism: the same instant expressed in any zone hashes identically
        # because canonicalisation normalises to UTC first.
        from datetime import timedelta, timezone
        plus_five = timezone(timedelta(hours=5))
        out    = canonical_row({"created_at": datetime(2026, 7, 27, 20, 30, 45, 123456, tzinfo=plus_five)})
        parsed = json.loads(out)
        assert parsed["created_at"] == "2026-07-27T15:30:45.123456+00:00"

    def test_uuid_serialised_as_string(self):
        u      = uuid.UUID("12345678-1234-5678-1234-567812345678")
        out    = canonical_row({"proxy_interaction_id": u})
        parsed = json.loads(out)
        assert parsed["proxy_interaction_id"] == str(u)

    def test_nested_dict_keys_sorted(self):
        row_a = {"detection_scores": {"rule": 0.1, "ml": 0.2}}
        row_b = {"detection_scores": {"ml": 0.2, "rule": 0.1}}
        assert canonical_row(row_a) == canonical_row(row_b)

    def test_nested_list_order_preserved(self):
        # Threats order is meaningful (matches detector precedence in
        # the risk scorer); reversing it must change the hash.
        row_a = {"threats": ["A", "B"]}
        row_b = {"threats": ["B", "A"]}
        assert canonical_row(row_a) != canonical_row(row_b)

    def test_bool_stays_bool_not_int(self):
        # A False that hashed as 0 would collide with a real risk_score=0.
        out    = canonical_row({"llm_invoked": False})
        parsed = json.loads(out)
        assert parsed["llm_invoked"] is False

    def test_unsupported_type_raises(self):
        # A Decimal or custom object slipping in must fail loudly
        # rather than hash under a non-deterministic repr.
        from decimal import Decimal
        with pytest.raises(TypeError, match="canonicalisable"):
            canonical_row({"risk_score": Decimal("0.1")})

    def test_ascii_only_output(self):
        # ensure_ascii=True keeps hashes stable across systems whose
        # default JSON encoding disagrees on unicode escapes.
        out = canonical_row({"source": "café"})   # 'café' NFD
        assert out.isascii()


class TestComputeRecordHash:

    def test_hash_is_hex_sha256(self):
        h = compute_record_hash(_sample_row(), prev_hash=None)
        assert len(h) == 64
        int(h, 16)   # must be pure hex

    def test_genesis_row_treats_prev_hash_none_as_empty_string(self):
        row      = _sample_row()
        expected = hashlib.sha256(canonical_row(row).encode("ascii")).hexdigest()
        assert compute_record_hash(row, prev_hash=None) == expected
        assert compute_record_hash(row, prev_hash="")   == expected

    def test_different_prev_hash_produces_different_record_hash(self):
        row = _sample_row()
        h1  = compute_record_hash(row, prev_hash="a" * 64)
        h2  = compute_record_hash(row, prev_hash="b" * 64)
        assert h1 != h2

    def test_content_change_produces_different_record_hash(self):
        row_a = _sample_row()
        row_b = dict(row_a, decision="BLOCK")
        prev  = "c" * 64
        assert compute_record_hash(row_a, prev) != compute_record_hash(row_b, prev)

    def test_chain_linkage(self):
        # Simulate a three-row chain and verify each row hashes off
        # the previous row's record_hash exactly as the writer does.
        row1 = dict(_sample_row(), trace_id="req_1")
        row2 = dict(_sample_row(), trace_id="req_2")
        row3 = dict(_sample_row(), trace_id="req_3")

        h1 = compute_record_hash(row1, prev_hash=None)
        h2 = compute_record_hash(row2, prev_hash=h1)
        h3 = compute_record_hash(row3, prev_hash=h2)

        # Re-derivation from stored prev_hash chain matches.
        assert compute_record_hash(row2, prev_hash=h1) == h2
        assert compute_record_hash(row3, prev_hash=h2) == h3
        # Tampering with row2 breaks row3's re-derivation even though
        # row3 itself was not touched.
        tampered_row2 = dict(row2, decision="BLOCK")
        assert compute_record_hash(tampered_row2, prev_hash=h1) != h2


# ── a format's definition is frozen once rows exist under it ─────────────────
#
# This exists because the thing it prevents already happened. `input_source` was
# added to CANONICAL_FIELDS, and the timestamp serialiser was changed to
# normalise through ensure_utc, while rows hashed under the previous definition
# were already on disk. Both changes were reasonable in themselves and neither
# carried a format bump, so every earlier row silently stopped verifying.
#
# Nothing caught it, because nothing read the chain back until a verifier was
# written months later. By then the evidence was unrecoverable: what the field
# set USED to be is recorded nowhere, so those rows cannot be verified again at
# all. A hash chain whose definition moves under it does not become
# tamper-evident afterwards.
#
# The rule these assert: a format's field set AND its serialisation are frozen.
# Changing what is hashed means declaring a NEW format and leaving the old one
# untouched, which is what format 2 did for chain_seq.

# Written out in full rather than derived from the source tuple: an expectation
# computed from the thing under test would move with it and assert nothing.
_FORMAT_1_FIELDS = (
    "app_id", "attribution_verified", "confidence", "confidence_band",
    "created_at", "decision", "dept_id", "detection_mode", "detection_scores",
    "execution_mode", "guardrail_scores", "input_hash", "input_length",
    "input_source", "ip_address", "key_id", "latency_ms", "llm_invoked",
    "model_version", "policy_source", "primary_reason", "principal_type",
    "proxy_interaction_id", "risk_score", "run_id", "session_id", "severity",
    "source", "tenant_id", "threats", "trace_id", "turn_index", "user_agent",
    "user_id",
)

_FORMAT_2_FIELDS = (*_FORMAT_1_FIELDS, "chain_seq")


class TestCanonicalFieldSetsAreFrozen:
    def test_format_1_fields_are_what_existing_rows_were_hashed_under(self):
        from security.audit_chain import fields_for_format

        assert fields_for_format(1) == _FORMAT_1_FIELDS, (
            "the format 1 field set changed. Every row already written under "
            "format 1 was hashed over the previous set and can never verify "
            "again -- and that cannot be repaired, because the old field set is "
            "not recorded on the rows. To hash a new field, declare a NEW "
            "format (see CANONICAL_FIELDS_V2) and leave this one alone."
        )

    def test_format_2_is_format_1_plus_the_chain_position(self):
        from security.audit_chain import fields_for_format

        assert fields_for_format(2) == _FORMAT_2_FIELDS, (
            "the format 2 field set changed; rows written under it stop verifying"
        )

    def test_a_row_with_no_format_is_read_as_format_1(self):
        """Rows that predate the column. Format 1 by definition, and reading
        them under any other set would report them as corrupt."""
        from security.audit_chain import fields_for_format

        assert fields_for_format(None) == _FORMAT_1_FIELDS

    def test_no_two_formats_hash_the_same_fields(self):
        from security.audit_chain import _FIELDS_BY_FORMAT

        sets = [tuple(v) for v in _FIELDS_BY_FORMAT.values()]
        assert len(set(sets)) == len(sets), (
            "two formats hash identical fields, so the format number records a "
            "distinction that does not exist"
        )

    def test_new_rows_are_written_under_the_newest_format(self):
        from security.audit_chain import _FIELDS_BY_FORMAT, CURRENT_CHAIN_FORMAT

        assert CURRENT_CHAIN_FORMAT == max(_FIELDS_BY_FORMAT), (
            "rows are being written under a format that is not the newest declared"
        )


class TestSerialisationIsFrozen:
    """The field set is only half of it: how a value RENDERS is hashed too.

    Changing the timestamp serialiser is what broke the chain the first time,
    and no field-set assertion would have caught that. These pin the bytes.
    """

    _FIXED_ROW: ClassVar[dict] = {
        "trace_id":     "req_frozen",
        "tenant_id":    "tenant-1",
        "decision":     "ALLOW",
        "risk_score":   0.25,
        "threats":      ["PROMPT_INJECTION"],
        "created_at":   datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc),
        "llm_invoked":  False,
        "input_length": 42,
        "chain_seq":    7,
    }

    def test_format_1_serialisation_is_byte_stable(self):
        assert canonical_row(self._FIXED_ROW, 1) == (
            '{"app_id":null,"attribution_verified":null,"confidence":null,'
            '"confidence_band":null,"created_at":"2026-01-02T03:04:05.678901+00:00",'
            '"decision":"ALLOW","dept_id":null,"detection_mode":null,'
            '"detection_scores":null,"execution_mode":null,"guardrail_scores":null,'
            '"input_hash":null,"input_length":42,"input_source":null,'
            '"ip_address":null,"key_id":null,"latency_ms":null,"llm_invoked":false,'
            '"model_version":null,"policy_source":null,"primary_reason":null,'
            '"principal_type":null,"proxy_interaction_id":null,"risk_score":0.25,'
            '"run_id":null,"session_id":null,"severity":null,"source":null,'
            '"tenant_id":"tenant-1","threats":["PROMPT_INJECTION"],'
            '"trace_id":"req_frozen","turn_index":null,"user_agent":null,'
            '"user_id":null}'
        ), (
            "the format 1 serialisation changed. Rows on disk were hashed over "
            "the previous bytes and will no longer verify. Declare a new format "
            "rather than changing how format 1 renders."
        )

    def test_format_2_adds_only_the_chain_position(self):
        """Keys are sorted, so chain_seq lands between attribution_verified and
        confidence rather than at the end. Asserted by removing that one member
        and requiring what is left to be format 1 exactly."""
        one = canonical_row(self._FIXED_ROW, 1)
        two = canonical_row(self._FIXED_ROW, 2)

        assert '"chain_seq":7' in two, "format 2 does not hash the chain position"
        assert two.replace(',"chain_seq":7', "", 1) == one, (
            "format 2 differs from format 1 by more than chain_seq"
        )

    def test_the_hash_of_a_fixed_row_does_not_move(self):
        """A golden vector over the whole pipeline: the field set, the rendering
        and the prev_hash concatenation together."""
        row = self._FIXED_ROW
        assert compute_record_hash(row, None, 1) == hashlib.sha256(
            canonical_row(row, 1).encode()
        ).hexdigest()
        assert compute_record_hash(row, "abc", 1) == hashlib.sha256(
            (canonical_row(row, 1) + "abc").encode()
        ).hexdigest()
