# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Correlation, so one agent's activity can be reconstructed afterwards.

The identifiers are the only way an investigator gets from "something was
blocked" to "here is the call it came from and what happened either side of it".
A timeline that groups the wrong things, or splits things that belong together,
is worse than none: it sends the investigation in a direction the evidence does
not support.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from mcp import types

from mcp_gateway.config import GatewayConfig, ServerConfig
from mcp_gateway.correlation import Correlation
from mcp_gateway.interceptors.enforcing import EnforcingInterceptor
from mcp_gateway.interceptors.scan_result import ToolResultScanner
from mcp_gateway.interceptors.scan_tools import ToolDefinitionScanner
from mcp_gateway.interceptors.validate_call import ToolCallValidator
from mcp_gateway.proxy import Gateway
from mcp_gateway.scanner import Scanner, Verdict
from mcp_gateway.session import DownstreamPool, DownstreamServer


@dataclass
class _Recording:
    """Records the correlation carried by every scan."""

    seen: list[dict] = field(default_factory=list)

    async def scan(self, text: str, *, source: str, trace_id: str,
                   turn_index: int | None = None) -> Verdict:
        self.seen.append({"source": source, "trace": trace_id, "turn": turn_index})
        return Verdict(blocked=False, sanitized=None, reason="ALLOWED", trace_id=trace_id)


class _Session:
    def __init__(self, tools):
        self._tools = tools

    async def list_tools(self):
        return types.ListToolsResult(tools=self._tools)

    async def call_tool(self, name, arguments):
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")])


def _tool(name="read"):
    return types.Tool(name=name, description="d", inputSchema={"type": "object"})


async def _gateway(scanner, correlation=None):
    config = GatewayConfig(servers=(ServerConfig(name="files", command=("echo",)),))
    tools  = [_tool()]
    gw = Gateway(config, DownstreamPool(), EnforcingInterceptor(
        tool_definitions=ToolDefinitionScanner(scanner),
        tool_results=ToolResultScanner(scanner),
        tool_calls=ToolCallValidator(config, scanner),
    ), correlation=correlation)
    gw.routes.add_server(
        "files", DownstreamServer(config=config.servers[0], session=_Session(tools)), tools)
    return gw


def _call(name="files__read"):
    return types.CallToolRequestParams(name=name, arguments={"a": "b"})


# ---------------------------------------------------------------------------
# the rule: a result inherits its call's turn
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_result_scan_inherits_the_turn_of_its_originating_call():
    """The argument scan and the result scan are two decisions about ONE agent
    action, and must share an index.

    If the result took a fresh index, a blocked result and the call that
    produced it would appear as unrelated rows, leaving an investigator to
    re-associate them by hand -- exactly when they are under time pressure.
    """
    scanner = _Recording()
    gateway = await _gateway(scanner)

    await gateway.on_call_tool(None, _call())

    turns = [s["turn"] for s in scanner.seen]
    assert len(turns) == 2, f"expected an argument scan and a result scan, got {scanner.seen}"
    assert turns[0] == turns[1], (
        f"the result scan took turn {turns[1]} instead of inheriting {turns[0]}"
    )


@pytest.mark.asyncio
async def test_the_result_scan_does_not_advance_the_counter():
    """Inheriting is not the same as not incrementing: the next request must
    still get the next index."""
    scanner     = _Recording()
    correlation = Correlation()
    gateway     = await _gateway(scanner, correlation)

    await gateway.on_call_tool(None, _call())
    first = correlation.turn_index
    await gateway.on_call_tool(None, _call())

    assert correlation.turn_index == first + 1, (
        "a second call did not advance the turn, so two actions share one index"
    )


@pytest.mark.asyncio
async def test_separate_calls_get_separate_turns():
    scanner = _Recording()
    gateway = await _gateway(scanner)

    await gateway.on_call_tool(None, _call())
    await gateway.on_call_tool(None, _call())

    turns = [s["turn"] for s in scanner.seen]
    assert turns[0] == turns[1] and turns[2] == turns[3]
    assert turns[2] > turns[1], "the second call reused the first call's turn"


@pytest.mark.asyncio
async def test_a_listing_is_one_turn_however_many_definitions_it_judges():
    """A listing is one agent request. Its definitions belong to it, not to a
    turn each."""
    scanner = _Recording()
    config  = GatewayConfig(servers=(ServerConfig(name="files", command=("echo",)),))
    tools   = [_tool("read"), _tool("write"), _tool("stat")]
    gw = Gateway(config, DownstreamPool(), EnforcingInterceptor(
        tool_definitions=ToolDefinitionScanner(scanner),
        tool_results=ToolResultScanner(scanner),
        tool_calls=ToolCallValidator(config, scanner),
    ))
    gw.routes.add_server(
        "files", DownstreamServer(config=config.servers[0], session=_Session(tools)), tools)

    await gw.on_list_tools(None, None)

    turns = {s["turn"] for s in scanner.seen}
    assert len(scanner.seen) == 3, "not every definition was judged"
    assert turns == {1}, f"one listing produced turns {turns}"


# ---------------------------------------------------------------------------
# identity and isolation
# ---------------------------------------------------------------------------

def test_a_run_and_a_session_are_distinct_identifiers():
    """The same span today, different meanings to the timeline that reads them.

    Keeping them separate means a transport that later multiplexes connections
    needs no reinterpretation of records already written.
    """
    scope = Correlation()

    assert scope.session_id != scope.run_id
    assert scope.session_id and scope.run_id


def test_two_gateway_processes_cannot_share_a_timeline():
    """Parallel agents run in separate processes, so their activity must not
    merge. The isolation comes from the runtime model; this pins it."""
    first, second = Correlation(), Correlation()

    assert first.run_id     != second.run_id
    assert first.session_id != second.session_id


def test_every_decision_gets_its_own_trace():
    scope   = Correlation()
    traces  = {scope.trace() for _ in range(50)}

    assert len(traces) == 50


def test_turns_start_at_one_and_increase():
    scope = Correlation()

    assert scope.turn_index == 0, "a turn was counted before any request"
    assert [scope.begin_turn() for _ in range(3)] == [1, 2, 3]


# ---------------------------------------------------------------------------
# what reaches the API
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_identifiers_reach_the_detection_api():
    """Without this the timeline endpoint has nothing to group by, and the trail
    stops at the gateway's own logs."""
    class _Client:
        def __init__(self): self.calls = []
        async def scan(self, text, *, mode, input_source, **kwargs):
            self.calls.append(kwargs)
            class _R:
                trace_id = "api"
                primary_reason = "NO_THREAT_DETECTED"
                sanitized_input = None
                is_blocked      = False
                is_sanitized    = False
                is_system_error = False
            return _R()

    client  = _Client()
    scanner = Scanner(client, session_id="sess-1", run_id="run-1")

    await scanner.scan("text", source="tool_output", trace_id="t", turn_index=7)

    sent = client.calls[0]
    assert sent["session_id"] == "sess-1"
    assert sent["run_id"]     == "run-1"
    assert sent["turn_index"] == 7
