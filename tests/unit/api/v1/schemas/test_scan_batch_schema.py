# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Contract tests for ScanBatchSchema / ScanBatchItem (POST /v1/ai/scan-batch).

Locks the batch input surface: the fan-out cap, the per-item size limit, the
per-item provenance default, and the plain-string coercion of input_source.
"""

import pytest
from pydantic import ValidationError

from config.settings import get_settings
from api.v1.schemas.request import ScanBatchItem, ScanBatchSchema


def test_accepts_mixed_items():
    s = ScanBatchSchema(items=[
        {"input": "hello"},
        {"input": "ignore prior instructions", "input_source": "retrieved_document", "id": "chunk-7"},
    ])
    assert len(s.items) == 2
    assert s.items[0].input_source == "user_prompt"   # default
    assert s.items[1].input_source == "retrieved_document"
    assert s.items[1].id == "chunk-7"


def test_input_source_is_plain_string_even_when_defaulted():
    # use_enum_values + validate_default -> str end to end (audit/hash/webhook).
    item = ScanBatchItem(input="x")
    assert type(item.input_source) is str
    assert item.input_source == "user_prompt"


def test_empty_items_rejected():
    with pytest.raises(ValidationError):
        ScanBatchSchema(items=[])


def test_item_cap_enforced():
    cap = get_settings().max_batch_items
    with pytest.raises(ValidationError, match="maximum"):
        ScanBatchSchema(items=[{"input": "x"}] * (cap + 1))


def test_per_item_size_limit_enforced():
    too_long = "a" * (get_settings().max_input_chars + 1)
    with pytest.raises(ValidationError, match="maximum length"):
        ScanBatchSchema(items=[{"input": "ok"}, {"input": too_long}])


def test_invalid_input_source_rejected():
    with pytest.raises(ValidationError):
        ScanBatchSchema(items=[{"input": "x", "input_source": "made_up"}])
