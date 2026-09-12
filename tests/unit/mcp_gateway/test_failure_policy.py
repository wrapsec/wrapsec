# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The documented failure policy, asserted as a whole.

Each control is tested where it lives; this file exists so the POLICY is
testable as one thing. A gateway's behaviour under failure is the part an
operator has to be able to rely on without reading the implementation, and a
policy that is only true one row at a time is a policy nobody can check.

The governing rule is that an unjudged payload is not a safe payload. Wherever
the gateway cannot obtain a verdict -- the API is down, a detector faulted, the
content is too large to judge -- it refuses, and records that it could not judge
rather than claiming the content was clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from mcp import types

from mcp_gateway.config import GatewayConfig, ServerConfig, ToolPolicy
from mcp_gateway.decision import TOOL_DENIED_BY_POLICY, TOOL_NOT_RESOLVED
from mcp_gateway.interceptors.enforcing import EnforcingInterceptor
from mcp_gateway.interceptors.scan_result import ToolResultScanner
from mcp_gateway.interceptors.scan_tools import ToolDefinitionScanner
from mcp_gateway.interceptors.validate_call import ToolCallValidator
from mcp_gateway.proxy import Gateway
from mcp_gateway.scanner import Scanner, Verdict
from mcp_gateway.session import DownstreamPool, DownstreamServer

# ---------------------------------------------------------------------------
# doubles
# ---------------------------------------------------------------------------

class _UnreachableClient:
    """A detection API that cannot be reached."""

    async def scan(self, text, *, mode, input_source, **kwargs):
        raise OSError("connection refused")


class _FaultingClient:
    """A detection API that answers, but reports its own fault on the result."""

    async def scan(self, text, *, mode, input_source, **kwargs):
        class _R:
            trace_id = "api"
            primary_reason = "SYSTEM_ERROR"
            is_blocked      = True
            is_sanitized    = False
            is_system_error = True
        return _R()


@dataclass
class _CleanScanner:
    seen: list[str] = field(default_factory=list)

    async def scan(self, text: str, *, source: str, trace_id: str,
                   turn_index: int | None = None) -> Verdict:
        self.seen.append(text)
        return Verdict(blocked=False, sanitized=None, reason="ALLOWED", trace_id=trace_id)


class _Session:
    def __init__(self, tools, result=None, raises=None):
        self._tools  = tools
        self._result = result
        self._raises = raises
        self.calls   = []

    async def list_tools(self):
        return types.ListToolsResult(tools=self._tools)

    async def call_tool(self, name, arguments):
        self.calls.append(name)
        if self._raises:
            raise self._raises
        return self._result or types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")])


def _tool(name="read"):
    return types.Tool(name=name, description="d", inputSchema={"type": "object"})


async def _gateway(scanner, *, session=None, allow=(), deny=()):
    config = GatewayConfig(servers=(ServerConfig(
        name="files", command=("echo",),
        tools=ToolPolicy(allow=tuple(allow), deny=tuple(deny)),
    ),))
    tools   = [_tool()]
    session = session or _Session(tools)
    gw = Gateway(config, DownstreamPool(), EnforcingInterceptor(
        tool_definitions=ToolDefinitionScanner(scanner),
        tool_results=ToolResultScanner(scanner),
        tool_calls=ToolCallValidator(config, scanner),
    ))
    gw.routes.add_server(
        "files", DownstreamServer(config=config.servers[0], session=session), tools,
    )
    return gw, session


def _body(result) -> str:
    return " ".join(b.text for b in (result.content or []) if getattr(b, "text", None))


# ---------------------------------------------------------------------------
# the policy, row by row
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_an_unreachable_detection_api_blocks_rather_than_forwards():
    """The governing rule. Content the gateway could not judge is not content it
    may forward, or the control was optional all along."""
    gw, session = await _gateway(Scanner(_UnreachableClient()))

    published = await gw.on_list_tools(None, None)
    assert published.tools == [], "tools were published with no way to judge them"

    result = await gw.on_call_tool(
        None, types.CallToolRequestParams(name="files__read", arguments={"a": "b"}))
    assert result.is_error is True
    assert session.calls == [], "a call was forwarded with no way to judge it"


@pytest.mark.asyncio
async def test_a_detector_fault_blocks():
    """The API answers, but reports that it could not evaluate. Without reading
    that flag a failed scan looks exactly like a clean one."""
    gw, _ = await _gateway(Scanner(_FaultingClient()))

    assert (await gw.on_list_tools(None, None)).tools == []


@pytest.mark.asyncio
async def test_content_too_large_to_judge_blocks_and_is_not_truncated():
    """Over the bound the content is refused, not partly judged.

    A verdict taken on the first N characters does not cover what was sent, and
    yet looks like one that does.
    """
    class _Counting:
        def __init__(self): self.calls = 0
        async def scan(self, text, *, mode, input_source, **kwargs):
            self.calls += 1

    oversized = types.Tool(
        name="read", description="x" * 500, inputSchema={"type": "object"},
    )
    client = _Counting()
    config = GatewayConfig(servers=(ServerConfig(name="files", command=("echo",)),))
    gw = Gateway(config, DownstreamPool(), EnforcingInterceptor(
        tool_definitions=ToolDefinitionScanner(Scanner(client, max_chars=50)),
        tool_results=ToolResultScanner(Scanner(client, max_chars=50)),
        tool_calls=ToolCallValidator(config, Scanner(client, max_chars=50)),
    ))
    gw.routes.add_server(
        "files",
        DownstreamServer(config=config.servers[0], session=_Session([oversized])),
        [oversized],
    )

    assert (await gw.on_list_tools(None, None)).tools == [], (
        "an oversized definition was published"
    )
    assert client.calls == 0, "oversized content was sent to the detector anyway"


@pytest.mark.asyncio
async def test_a_denied_tool_is_refused_and_never_forwarded():
    gw, session = await _gateway(_CleanScanner(), deny=("files__read",))

    result = await gw.on_call_tool(
        None, types.CallToolRequestParams(name="files__read", arguments={}))

    assert result.is_error is True
    assert session.calls == []
    assert TOOL_DENIED_BY_POLICY not in _body(result)   # the code stays internal


@pytest.mark.asyncio
async def test_an_unresolvable_tool_is_refused():
    gw, session = await _gateway(_CleanScanner())

    result = await gw.on_call_tool(
        None, types.CallToolRequestParams(name="files__missing", arguments={}))

    assert result.is_error is True
    assert session.calls == []
    assert TOOL_NOT_RESOLVED not in _body(result)


@pytest.mark.asyncio
async def test_a_downstream_tool_error_is_returned_as_that_tool_s_error():
    """A tool that failed still failed. The gateway does not convert a tool's own
    error into a security refusal, or an operator cannot tell them apart."""
    failing = _Session([_tool()], result=types.CallToolResult(
        content=[types.TextContent(type="text", text="disk is full")], is_error=True))
    gw, _ = await _gateway(_CleanScanner(), session=failing)

    result = await gw.on_call_tool(
        None, types.CallToolRequestParams(name="files__read", arguments={}))

    assert result.is_error is True
    assert "disk is full" in _body(result), "the tool's own error was replaced"
    assert "WrapSec" not in _body(result), "a tool error was dressed as a refusal"


@pytest.mark.asyncio
async def test_a_non_text_result_passes_safely():
    """Binary content is not scanned by this build. It must pass rather than
    crash, and must not be reported as judged."""
    picture = _Session([_tool()], result=types.CallToolResult(
        content=[types.ImageContent(type="image", data="AAAA", mimeType="image/png")]))
    scanner = _CleanScanner()
    gw, _   = await _gateway(scanner, session=picture)

    result = await gw.on_call_tool(
        None, types.CallToolRequestParams(name="files__read", arguments={}))

    assert result.is_error is False
    assert [b.type for b in result.content] == ["image"]


@pytest.mark.asyncio
async def test_an_allowed_call_with_a_clean_result_is_forwarded():
    """The policy has to permit the ordinary case, or it is not a policy but an
    outage."""
    gw, session = await _gateway(_CleanScanner(), allow=("files__read",))

    result = await gw.on_call_tool(
        None, types.CallToolRequestParams(name="files__read", arguments={"a": "b"}))

    assert result.is_error is False
    assert session.calls == ["read"]
    assert "ok" in _body(result)


def test_an_unsupported_mcp_package_refuses_to_start(monkeypatch):
    """A control whose API moved is not a control. Refusing beats running with
    it silently disabled."""
    import inspect

    from mcp.client.session import ClientSession

    from mcp_gateway.mcp_compat import UnsupportedMCPPackage, verify_mcp_package

    params = [p for p in inspect.signature(ClientSession.call_tool).parameters.values()
              if p.name != "allow_input_required"]

    async def _stripped(self, *a, **k):  # pragma: no cover - never called
        raise AssertionError

    _stripped.__signature__ = inspect.Signature(params)
    monkeypatch.setattr(ClientSession, "call_tool", _stripped)

    with pytest.raises(UnsupportedMCPPackage):
        verify_mcp_package()
