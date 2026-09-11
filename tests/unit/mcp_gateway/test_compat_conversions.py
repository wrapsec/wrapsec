# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Converting MCP types into gateway terms, and what deliberately does not convert."""

from __future__ import annotations

import pytest
from mcp import types

from mcp_gateway.mcp_compat import text_parts_of, to_tool_definition


def test_a_tool_definition_keeps_the_name_verbatim():
    """Unvalidated and attacker-influenceable, so it is carried as data and never
    normalized on the way in -- normalizing here would hide from routing what the
    downstream server actually said."""
    tool = types.Tool(name="weird name/here", description="d", inputSchema={"type": "object"})

    converted = to_tool_definition(tool)

    assert converted.name         == "weird name/here"
    assert converted.description  == "d"
    assert converted.input_schema == {"type": "object"}


def test_a_definition_without_a_schema_still_converts():
    tool = types.Tool(name="t", inputSchema={})
    assert to_tool_definition(tool).input_schema == {}


def test_text_parts_are_returned_in_order():
    result = types.CallToolResult(content=[
        types.TextContent(type="text", text="first"),
        types.TextContent(type="text", text="second"),
    ])
    assert text_parts_of(result) == ("first", "second")


def test_non_text_content_is_not_rendered_into_text():
    """V1 does not scan images or binary content.

    Inventing a textual stand-in would mean scanning something the agent never
    receives while forwarding something that was never scanned. Such parts are
    simply not returned here.
    """
    result = types.CallToolResult(content=[
        types.TextContent(type="text", text="caption"),
        types.ImageContent(type="image", data="AAAA", mimeType="image/png"),
    ])

    assert text_parts_of(result) == ("caption",), (
        "non-text content leaked into the text the scanner would see"
    )


@pytest.mark.parametrize("empty", [
    types.CallToolResult(content=[]),
    types.ListToolsResult(tools=[]),
])
def test_a_result_with_no_text_yields_nothing(empty):
    assert text_parts_of(empty) == ()
