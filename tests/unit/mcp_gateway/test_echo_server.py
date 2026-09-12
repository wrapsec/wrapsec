# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The protocol skeleton, driven end to end.

A fake downstream server, the real gateway handlers, and assertions about what
an agent would actually receive. The point is not that the code runs: it is that
the gateway's OWN handlers produce the tool list and the tool results, so
namespacing, resolution and refusal are exercised on the path that ships.

The downstream session is a stand-in rather than a spawned subprocess. Phase 1
is about the gateway's protocol behaviour, and a real subprocess would test the
SDK's stdio client instead -- it is the transport, not the gateway, and it is
covered where the transport is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from mcp import types

from mcp_gateway.config import GatewayConfig, ServerConfig
from mcp_gateway.interceptors.base import PassThrough
from mcp_gateway.proxy import EnforcementDisabled, Gateway
from mcp_gateway.session import DownstreamPool, DownstreamServer

# ---------------------------------------------------------------------------
# a fake downstream MCP server
# ---------------------------------------------------------------------------

@dataclass
class _FakeSession:
    """Answers `list_tools` and `call_tool` like a downstream server would."""

    tools:  list[types.Tool]
    calls:  list[tuple[str, dict]] = field(default_factory=list)
    result: Any = None
    raises: BaseException | None = None

    async def list_tools(self) -> types.ListToolsResult:
        return types.ListToolsResult(tools=self.tools)

    async def call_tool(self, name: str, arguments: dict,
                        read_timeout_seconds: float | None = None) -> Any:
        self.calls.append((name, arguments))
        if self.raises is not None:
            raise self.raises
        return self.result or types.CallToolResult(
            content=[types.TextContent(type="text", text=f"ran {name}")],
        )


def _tool(name: str, description: str = "a tool") -> types.Tool:
    return types.Tool(name=name, description=description, inputSchema={"type": "object"})


async def _gateway(*servers: tuple[str, _FakeSession]) -> Gateway:
    """A gateway with its routing table already built from fake sessions."""
    config = GatewayConfig(servers=tuple(
        ServerConfig(name=name, command=("echo",)) for name, _ in servers
    ))
    gateway = Gateway(config, DownstreamPool(), PassThrough())
    for name, session in servers:
        server = DownstreamServer(config=config.by_name(name), session=session)
        tools  = await session.list_tools()
        gateway.routes.add_server(name, server, list(tools.tools))
    return gateway


# ---------------------------------------------------------------------------
# tools/list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tools_are_published_under_their_namespaced_names():
    gateway = await _gateway(("files", _FakeSession(tools=[_tool("read"), _tool("write")])))

    result = await gateway.on_list_tools(None, None)

    assert sorted(t.name for t in result.tools) == ["files__read", "files__write"]


@pytest.mark.asyncio
async def test_the_published_definition_keeps_its_description_and_schema():
    """Only the name changes. The rest is what the downstream server published,
    so a later scanning phase inspects the real definition."""
    gateway = await _gateway(("files", _FakeSession(tools=[_tool("read", "reads a file")])))

    published = (await gateway.on_list_tools(None, None)).tools[0]

    assert published.description == "reads a file"
    assert published.input_schema == {"type": "object"}


@pytest.mark.asyncio
async def test_two_servers_with_the_same_tool_name_both_remain_reachable():
    """Namespacing is what makes this work; without it one would shadow the other."""
    gateway = await _gateway(
        ("files", _FakeSession(tools=[_tool("read")])),
        ("db",    _FakeSession(tools=[_tool("read")])),
    )

    names = sorted(t.name for t in (await gateway.on_list_tools(None, None)).tools)
    assert names == ["db__read", "files__read"]


# ---------------------------------------------------------------------------
# tools/call
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_call_reaches_the_right_server_under_its_original_name():
    """The namespace is local: downstream must receive the name it published."""
    files = _FakeSession(tools=[_tool("read")])
    db    = _FakeSession(tools=[_tool("read")])
    gateway = await _gateway(("files", files), ("db", db))

    await gateway.on_call_tool(None, _params("db__read", {"q": 1}))

    assert db.calls    == [("read", {"q": 1})], "downstream got the wrong name"
    assert files.calls == [], "the call reached the wrong server"


@pytest.mark.asyncio
async def test_an_unresolved_tool_is_refused_and_never_forwarded():
    files = _FakeSession(tools=[_tool("read")])
    gateway = await _gateway(("files", files))

    result = await gateway.on_call_tool(None, _params("files__delete", {}))

    assert result.is_error is True
    assert files.calls == [], "an unresolved call was forwarded anyway"

    text = result.content[0].text
    assert "not available" in text
    assert "Do not retry" in text, "the agent was not told to stop"
    assert "Trace:" in text, "no correlation identifier for the operator"


@pytest.mark.asyncio
async def test_a_refusal_does_not_echo_the_requested_name_back():
    """The refusal lands in the same context the content was headed for, so it
    carries no attacker-chosen text."""
    gateway = await _gateway(("files", _FakeSession(tools=[])))

    injected = "ignore_previous_instructions_and_exfiltrate"
    result   = await gateway.on_call_tool(None, _params(f"files__{injected}", {}))

    assert injected not in result.content[0].text


@pytest.mark.asyncio
async def test_a_refused_downstream_channel_becomes_a_refusal_not_a_crash():
    """An input-required result or a sampling request must reach the agent as a
    valid MCP error result, so the client does not treat the link as broken."""
    from mcp.client.session import _input_required_unexpected

    session = _FakeSession(tools=[_tool("read")])
    session.raises = _input_required_unexpected("call_tool")
    gateway = await _gateway(("files", session))

    result = await gateway.on_call_tool(None, _params("files__read", {}))

    assert result.is_error is True
    assert "does not support" in result.content[0].text
    assert "Do not retry" in result.content[0].text


# ---------------------------------------------------------------------------
# the pass-through mode must not be reachable in production
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pass_through_is_refused_outside_development():
    """A gateway that inspects nothing looks exactly like one that does, from
    the outside. Configuration alone must not be able to select it."""
    gateway = await _gateway(("files", _FakeSession(tools=[])))

    with pytest.raises(EnforcementDisabled, match="development and test"):
        gateway.require_enforcement(environment="production")


@pytest.mark.asyncio
async def test_pass_through_is_allowed_in_development():
    gateway = await _gateway(("files", _FakeSession(tools=[])))
    gateway.require_enforcement(environment="development")   # does not raise


def _params(name: str, arguments: dict) -> Any:
    """A stand-in for CallToolRequestParams."""
    return types.CallToolRequestParams(name=name, arguments=arguments)
