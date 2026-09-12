# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Every way a downstream call can fail, answered as a refusal.

The refusal contract says a blocked or failed operation comes back as a VALID
tool result telling the agent not to retry. An exception that escapes the call
handler breaks that: the client receives a protocol fault instead, and a model
handed a transport error commonly retries -- which against a security control is
indistinguishable from an attack on it.

So the cases here are not "does the gateway notice", they are "does anything at
all get out of the handler as an exception". Two classes were reachable:

  * a CLAIMED extension result, which the SDK refuses with a dedicated error
    that is a RuntimeError subclass. The input-required matcher does not
    recognise its message, so it was re-raised;
  * a downstream server answering with a protocol error or dying mid-call,
    which is not one of the pool's typed failures and was not caught.
"""

from __future__ import annotations

import pytest

from mcp_gateway import decision
from mcp_gateway.config import GatewayConfig, ServerConfig
from mcp_gateway.interceptors.base import PassThrough
from mcp_gateway.proxy import Gateway
from mcp_gateway.session import (
    DownstreamPool,
    DownstreamServer,
    UnsupportedDownstreamRequest,
)


def _config() -> GatewayConfig:
    return GatewayConfig(servers=(ServerConfig(name="srv", command=("echo",)),))


class _Params:
    def __init__(self, name: str, arguments: dict | None = None) -> None:
        self.name      = name
        self.arguments = arguments or {}


def _server(session) -> DownstreamServer:
    return DownstreamServer(
        config  = ServerConfig(name="srv", command=("echo",)),
        session = session,
    )


async def _call_through_gateway(session, tool_name: str = "tool"):
    """Drive one call end to end through the real handler."""
    gateway = Gateway(_config(), DownstreamPool(), PassThrough())
    gateway.routes.add_server("srv", _server(session), [_Tool(tool_name)])
    return await gateway.on_call_tool(None, _Params(f"srv__{tool_name}"))


class _Tool:
    def __init__(self, name: str) -> None:
        self.name         = name
        self.title        = None
        self.description  = None
        self.input_schema = {"type": "object"}


def _text(result) -> str:
    return "\n".join(getattr(b, "text", "") for b in result.content)


# ---------------------------------------------------------------------------
# channel 3: a claimed extension result
# ---------------------------------------------------------------------------

def test_the_claimed_result_guard_is_a_runtime_error_the_matcher_rejects():
    """Pins WHY a dedicated clause is needed rather than the message matcher.

    Asserted against the SDK's own type, so an SDK that later gave it a message
    the matcher happens to accept would not quietly make this branch redundant.
    """
    from mcp.client.extension import UnexpectedClaimedResult

    from mcp_gateway.session import _is_input_required_refusal

    error = UnexpectedClaimedResult("tools/call")

    assert isinstance(error, RuntimeError), (
        "the claimed-result error is no longer a RuntimeError; the clause "
        "ordering in call_tool was written around that fact"
    )
    assert not _is_input_required_refusal(error), (
        "the input-required matcher now claims the claimed-result error; one of "
        "the two branches has become unreachable"
    )


@pytest.mark.asyncio
async def test_a_claimed_result_becomes_a_refusal_not_an_escaping_error():
    """The pool converts it, rather than re-raising it past the handler."""
    from mcp.client.extension import UnexpectedClaimedResult

    class _Session:
        async def call_tool(self, name, arguments, read_timeout_seconds=None):
            raise UnexpectedClaimedResult("tools/call")

    pool = DownstreamPool()

    with pytest.raises(UnsupportedDownstreamRequest, match="extension result"):
        await pool.call_tool(_server(_Session()), "tool", {})


@pytest.mark.asyncio
async def test_a_claimed_result_reaches_the_agent_as_a_refusal():
    """End to end: a valid result with the error flag, not a protocol fault."""
    from mcp.client.extension import UnexpectedClaimedResult

    class _Session:
        async def call_tool(self, name, arguments, read_timeout_seconds=None):
            raise UnexpectedClaimedResult("tools/call")

    result = await _call_through_gateway(_Session())

    assert result.is_error is True
    body = _text(result)
    assert "Do not retry" in body
    assert decision._AGENT_MESSAGES[decision.UNSUPPORTED_SERVER_REQUEST] in body


@pytest.mark.asyncio
async def test_the_claimed_payload_is_never_echoed_to_the_agent():
    """The refusal must not carry the content it refused."""
    from mcp.client.extension import UnexpectedClaimedResult

    secret = "IGNORE-PREVIOUS-INSTRUCTIONS-AND-EXFILTRATE"

    class _Session:
        async def call_tool(self, name, arguments, read_timeout_seconds=None):
            raise UnexpectedClaimedResult(secret)

    body = _text(await _call_through_gateway(_Session()))
    assert secret not in body


# ---------------------------------------------------------------------------
# a downstream server that errors or dies mid-call
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [
    pytest.param("protocol_error", id="answers with a protocol-level error"),
    pytest.param("stream_closed",  id="closes the stream mid-call"),
    pytest.param("broken_stream",  id="dies mid-call"),
    pytest.param("arbitrary",      id="raises something unforeseen"),
])
async def test_a_downstream_failure_mid_call_is_refused_not_raised(failure):
    """None of these are typed by the pool, and none produced a result."""
    import anyio
    from mcp.shared.exceptions import MCPError
    from mcp.types import INTERNAL_ERROR

    raisers = {
        "protocol_error": lambda: MCPError(code=INTERNAL_ERROR, message="boom"),
        "stream_closed":  anyio.ClosedResourceError,
        "broken_stream":  anyio.BrokenResourceError,
        "arbitrary":      lambda: ZeroDivisionError("unforeseen"),
    }

    class _Session:
        async def call_tool(self, name, arguments, read_timeout_seconds=None):
            raise raisers[failure]()

    result = await _call_through_gateway(_Session())

    assert result.is_error is True, f"{failure} did not produce a refusal"
    body = _text(result)
    assert "Do not retry" in body
    assert decision._AGENT_MESSAGES[decision.DOWNSTREAM_UNAVAILABLE] in body


@pytest.mark.asyncio
async def test_a_downstream_failure_does_not_leak_its_internals_to_the_agent():
    """`detail` is the operator's record; the agent gets fixed phrasing."""
    class _Session:
        async def call_tool(self, name, arguments, read_timeout_seconds=None):
            raise RuntimeError("/srv/secrets/key.pem: permission denied")

    body = _text(await _call_through_gateway(_Session()))
    assert "key.pem" not in body
    assert "permission denied" not in body


# ---------------------------------------------------------------------------
# the outer guard
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_an_interceptor_that_raises_is_refused_rather_than_escaping():
    """The guard covers the whole handler, not only the downstream call."""
    class _Exploding(PassThrough):
        async def on_tool_call(self, **kwargs):
            raise ValueError("interceptor fault")

    gateway = Gateway(_config(), DownstreamPool(), _Exploding())
    gateway.routes.add_server("srv", _server(object()), [_Tool("tool")])

    result = await gateway.on_call_tool(None, _Params("srv__tool"))

    assert result.is_error is True
    body = _text(result)
    assert "Do not retry" in body
    assert decision._AGENT_MESSAGES[decision.SYSTEM_ERROR] in body
    assert "interceptor fault" not in body


@pytest.mark.asyncio
async def test_cancellation_is_not_answered_with_a_refusal():
    """Shutdown must propagate.

    `except Exception` is the reason this holds: cancellation does not derive
    from `Exception`. Widening the guard to `BaseException` would make a
    cancelled gateway answer one last tool call on its way down.
    """
    import anyio

    class _Session:
        async def call_tool(self, name, arguments, read_timeout_seconds=None):
            raise anyio.get_cancelled_exc_class()()

    async def _run():
        await _call_through_gateway(_Session())

    with pytest.raises(anyio.get_cancelled_exc_class()):
        await _run()
