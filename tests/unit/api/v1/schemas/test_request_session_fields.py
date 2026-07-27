# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Contract tests for the optional session tracking fields added to
AIRequestSchema in v1.2.0 commit #1.

The backend does not yet persist these fields - Alembic column additions
land in v1.2.0 commit #2. This module locks the Pydantic contract so SDK
kwargs pass validation today and the persistence commit only has to hook
into an already-stable input surface.
"""

import pytest
from pydantic import ValidationError

from api.v1.schemas.request import AIRequestSchema


def _base(**overrides):
    body = {"input": "hello"}
    body.update(overrides)
    return body


class TestSessionId:
    def test_accepts_uuid_like(self):
        req = AIRequestSchema(**_base(session_id="sess_01HXYZABC123"))
        assert req.session_id == "sess_01HXYZABC123"

    def test_accepts_allowed_symbols(self):
        req = AIRequestSchema(**_base(session_id="a.b:c-d_e"))
        assert req.session_id == "a.b:c-d_e"

    def test_defaults_to_none(self):
        req = AIRequestSchema(**_base())
        assert req.session_id is None

    def test_rejects_empty_string(self):
        with pytest.raises(ValidationError):
            AIRequestSchema(**_base(session_id=""))

    def test_rejects_over_max_length(self):
        with pytest.raises(ValidationError):
            AIRequestSchema(**_base(session_id="a" * 201))

    def test_rejects_disallowed_chars(self):
        for bad in ["with space", "with/slash", "with@at", "with#hash", "unicode-é"]:
            with pytest.raises(ValidationError):
                AIRequestSchema(**_base(session_id=bad))


class TestRunId:
    def test_accepts_valid(self):
        req = AIRequestSchema(**_base(run_id="run_abc.123"))
        assert req.run_id == "run_abc.123"

    def test_defaults_to_none(self):
        req = AIRequestSchema(**_base())
        assert req.run_id is None

    def test_rejects_over_max_length(self):
        with pytest.raises(ValidationError):
            AIRequestSchema(**_base(run_id="r" * 201))

    def test_rejects_disallowed_chars(self):
        with pytest.raises(ValidationError):
            AIRequestSchema(**_base(run_id="bad char"))


class TestTurnIndex:
    def test_accepts_zero(self):
        req = AIRequestSchema(**_base(turn_index=0))
        assert req.turn_index == 0

    def test_accepts_upper_bound(self):
        req = AIRequestSchema(**_base(turn_index=10000))
        assert req.turn_index == 10000

    def test_defaults_to_none(self):
        req = AIRequestSchema(**_base())
        assert req.turn_index is None

    def test_rejects_negative(self):
        with pytest.raises(ValidationError):
            AIRequestSchema(**_base(turn_index=-1))

    def test_rejects_over_upper_bound(self):
        with pytest.raises(ValidationError):
            AIRequestSchema(**_base(turn_index=10001))


class TestCombination:
    def test_all_three_fields_together(self):
        req = AIRequestSchema(
            **_base(session_id="s1", turn_index=3, run_id="r1")
        )
        assert req.session_id == "s1"
        assert req.turn_index == 3
        assert req.run_id     == "r1"

    def test_session_id_and_run_id_are_independent(self):
        req = AIRequestSchema(**_base(session_id="s1"))
        assert req.session_id == "s1"
        assert req.run_id is None
