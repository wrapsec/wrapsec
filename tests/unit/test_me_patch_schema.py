# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for the /me patch schema locale boundary:

    HTTP request -> max_length(35) -> allowlist validator -> DB VARCHAR(35)

max_length caps an oversized request before the validator runs and mirrors the
users.locale column. No DB or app context is exercised -- this is the Pydantic
model in isolation.
"""

import pytest
from pydantic import ValidationError

from api.v1.endpoints.auth import MePatchSchema


def test_locale_accepts_supported_null_and_omitted():
    assert MePatchSchema(locale="en").locale == "en"
    assert MePatchSchema(locale="de").locale == "de"    # enabled in locales/_meta.json
    assert MePatchSchema(locale="EN").locale == "en"    # canonicalized to allowlist spelling
    assert MePatchSchema(locale=None).locale is None    # explicit clear
    assert MePatchSchema().locale is None               # omitted -> unset


def test_locale_rejects_unsupported():
    # 'zz' is unassigned: passes the length gate, fails the allowlist.
    with pytest.raises(ValidationError):
        MePatchSchema(locale="zz")


def test_locale_rejects_overlong():
    with pytest.raises(ValidationError) as exc:
        MePatchSchema(locale="x" * 36)
    assert any(e["loc"] == ("locale",) and e["type"] == "string_too_long"
               for e in exc.value.errors())


def test_max_length_gate_precedes_allowlist():
    # 35 chars is within the length cap, so it reaches (and fails) the allowlist
    # validator instead -- proving max_length is the first gate, not the last.
    with pytest.raises(ValidationError) as exc:
        MePatchSchema(locale="x" * 35)
    assert all(e["type"] != "string_too_long" for e in exc.value.errors())
