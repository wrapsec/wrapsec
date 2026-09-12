# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A downstream tool that never answers, against a real subprocess.

Without a bound this hangs the request for the life of the process. stdio is one
client per process, so there is nothing else to serve and no other request to
make progress: one unresponsive tool takes that agent down.

Driven as a subprocess speaking raw protocol, because the behaviour under test
belongs to the client's own timeout machinery. A fake that raised on demand
would assert that the gateway handles an exception it was handed, not that the
bound is armed on the path that ships.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from mcp import types

from mcp_gateway import decision
from mcp_gateway.config import GatewayConfig, ServerConfig
from mcp_gateway.interceptors.base import PassThrough
from mcp_gateway.proxy import Gateway
from mcp_gateway.session import DownstreamPool, DownstreamServer

_ROOT   = Path(__file__).resolve().parents[3]
_PY     = str(_ROOT / ".venv" / "bin" / "python")
_SERVER = str(Path(__file__).parent / "_slow_servers.py")

# Short enough to keep the suite quick, long enough that a working call is never
# cut off by it. The SHIPPED default is two minutes; see config.DEFAULT_CALL_TIMEOUT_S.
_TIMEOUT_S = 2.0

pytestmark = pytest.mark.skipif(
    not Path(_PY).exists(), reason="the project interpreter is required",
)


def _text(result) -> str:
    return " ".join(b.text for b in (result.content or []) if getattr(b, "text", None))


class _Harness:
    """One live connection, with the gateway's own handlers in front of it."""

    def __init__(self, gateway: Gateway) -> None:
        self._gateway = gateway

    async def call(self, tool: str):
        return await self._gateway.on_call_tool(
            None, types.CallToolRequestParams(name=f"slow__{tool}", arguments={}),
        )


async def _connected(timeout_s: float = _TIMEOUT_S):
    """Yield a harness bound to a real hanging server."""
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    server_config = ServerConfig(
        name="slow", command=(_PY, _SERVER), call_timeout_s=timeout_s,
    )
    config = GatewayConfig(servers=(server_config,))

    params = StdioServerParameters(command=_PY, args=[_SERVER])
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        gateway = Gateway(config, DownstreamPool(), PassThrough())
        tools   = (await session.list_tools()).tools
        gateway.routes.add_server(
            "slow", DownstreamServer(config=server_config, session=session), tools,
        )
        yield _Harness(gateway)


@pytest.mark.asyncio
async def test_a_hanging_tool_is_refused_rather_than_hanging_the_agent():
    """The bound fires, and the agent gets a refusal it is told not to retry."""
    async for harness in _connected():
        started = time.monotonic()
        result  = await harness.call("hang")
        elapsed = time.monotonic() - started

        assert result.is_error is True, "the hanging call did not produce a refusal"
        body = _text(result)
        assert decision._AGENT_MESSAGES[decision.DOWNSTREAM_UNAVAILABLE] in body
        assert "Do not retry" in body
        assert elapsed < _TIMEOUT_S * 4, (
            f"the call took {elapsed:.1f}s against a {_TIMEOUT_S}s bound; the "
            f"timeout is not arming"
        )


@pytest.mark.asyncio
async def test_the_refusal_names_no_internals():
    """The agent-facing text must not carry SDK or timeout detail."""
    async for harness in _connected():
        body = _text(await harness.call("hang")).lower()

        for leak in ("timeout", "timed out", "mcperror", "-32001",
                     "read_timeout_seconds", "traceback"):
            assert leak not in body, f"the refusal leaks {leak!r}: {body}"


@pytest.mark.asyncio
async def test_the_gateway_stays_usable_after_a_timeout():
    """A timed-out call must not poison the connection.

    If it did, one unresponsive tool would cost the agent every other tool on
    that server, which is a larger outage than the one being contained.
    """
    async for harness in _connected():
        timed_out = await harness.call("hang")
        assert timed_out.is_error is True

        after = await harness.call("ping")
        assert after.is_error is False, (
            f"the connection did not survive the timeout: {_text(after)}"
        )
        assert "pong" in _text(after)


@pytest.mark.asyncio
async def test_the_timed_out_call_is_not_retried():
    """Asked of the SERVER, which is the only witness that cannot be fooled.

    A retry would hang again, and a gateway that retried into an unresponsive
    tool would multiply the outage it is containing.
    """
    async for harness in _connected():
        await harness.call("hang")

        counted = await harness.call("calls")
        assert counted.is_error is False
        assert _text(counted).strip() == "1", (
            f"the downstream server saw {_text(counted).strip()} hang calls; the "
            f"gateway retried a call it had already refused"
        )


@pytest.mark.asyncio
async def test_a_tool_that_answers_in_time_is_unaffected():
    """The bound must not turn working tools into refusals."""
    async for harness in _connected():
        result = await harness.call("ping")

        assert result.is_error is False
        assert "pong" in _text(result)
