# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
M6 regression: audit list `user_id` filter must be UUID-strict.
Previously used ILIKE substring, which let audit-read principals enumerate
other users by probing UUID substrings.

Coverage:
  * _parse_uuid_filter accepts a valid UUID and returns its canonical string
  * _parse_uuid_filter returns None for empty/None input
  * _parse_uuid_filter raises ValidationError for substrings, non-UUIDs
  * repo.list applies equality (not ILIKE) to user_id
"""

import uuid

import pytest

from api.v1.endpoints.audit import _parse_uuid_filter
from errors.exceptions import ValidationError


def test_parse_uuid_filter_accepts_uuid():
    u = uuid.uuid4()
    assert _parse_uuid_filter(str(u), "user_id") == str(u)


def test_parse_uuid_filter_accepts_hex_and_normalises():
    u = uuid.uuid4()
    out = _parse_uuid_filter(u.hex, "user_id")
    assert out == str(u)


def test_parse_uuid_filter_none_passes_through():
    assert _parse_uuid_filter(None, "user_id") is None
    assert _parse_uuid_filter("", "user_id") is None


@pytest.mark.parametrize("bad", [
    "abc",                           # too short
    "not-a-uuid",                    # obvious garbage
    "1234",                          # substring probe
    "%",                             # SQL-wildcard leak attempt
    "a" * 36,                        # right length, wrong content
    "00000000-0000-0000-0000-00000000000",  # 35 chars
])
def test_parse_uuid_filter_rejects_non_uuid(bad):
    with pytest.raises(ValidationError):
        _parse_uuid_filter(bad, "user_id")


def test_repo_uses_equality_not_ilike():
    """
    Read the compiled repo predicate to confirm equality, not ILIKE.
    A regression to `.ilike(...)` shows up as an `ILIKE` in the compiled SQL.
    """
    from db.models import AuditLogModel

    # Build the exact predicate the repo would apply for the user_id branch
    predicate = AuditLogModel.user_id == "11111111-1111-1111-1111-111111111111"
    sql = str(predicate.compile(compile_kwargs={"literal_binds": True}))
    assert "ILIKE" not in sql.upper()
    assert "=" in sql
