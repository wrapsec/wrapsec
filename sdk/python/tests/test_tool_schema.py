# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Unit tests for the function-calling / tool manifest (wrapsec_scan)."""

from __future__ import annotations

import json

import pytest
from wrapsec import SCAN_TOOL_NAME, anthropic_tool, openai_tool, scan_tool_schema
from wrapsec.tool_schema import INPUT_SOURCES, SCAN_TOOL_PARAMETERS


def test_canonical_schema_shape():
    s = scan_tool_schema()
    assert s["name"] == "wrapsec_scan"
    assert isinstance(s["description"], str) and s["description"]
    p = s["parameters"]
    assert p["type"] == "object"
    assert set(p["required"]) == {"text"}
    assert p["additionalProperties"] is False
    assert p["properties"]["text"]["type"] == "string"


def test_input_source_enum_and_default():
    p = SCAN_TOOL_PARAMETERS
    assert p["properties"]["input_source"]["enum"] == INPUT_SOURCES
    assert p["properties"]["input_source"]["default"] == "user_prompt"


def test_openai_tool_format():
    t = openai_tool()
    assert t["type"] == "function"
    assert t["function"]["name"] == "wrapsec_scan"
    assert "parameters" in t["function"]


def test_anthropic_tool_format():
    t = anthropic_tool()
    assert t["name"] == "wrapsec_scan"
    assert t["input_schema"] == SCAN_TOOL_PARAMETERS
    assert "parameters" not in t   # Anthropic uses input_schema, not parameters


def test_all_forms_json_serializable():
    for t in (scan_tool_schema(), openai_tool(), anthropic_tool()):
        json.dumps(t)   # must not raise


def test_name_constant_matches():
    assert SCAN_TOOL_NAME == scan_tool_schema()["name"] == "wrapsec_scan"


def test_input_sources_match_server_enum():
    # Cross-check the SDK mirror stays in sync with the server-side enum. Runs in
    # the repo where `domain` is importable; skipped when the SDK is installed
    # standalone (its published wheel does not ship the server package).
    try:
        from domain.enums import InputSource
    except Exception:
        pytest.skip("domain not importable (SDK installed standalone)")
    assert INPUT_SOURCES == [s.value for s in InputSource]
