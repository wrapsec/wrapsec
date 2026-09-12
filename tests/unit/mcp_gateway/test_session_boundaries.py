# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The two channels V1 refuses rather than forwards.

A downstream MCP server can ask the client to run an inference or to collect
input from the user. On legacy protocol revisions it asks through `sampling/*`;
at 2026-07-28 that channel is gone and the same asks arrive inside a tool result
as an `InputRequiredResult`. V1 inspects neither, so it serves neither.

The content behind both is server-authored -- a system prompt, message text, a
URL put in front of a user -- so forwarding it uninspected is the indirect
injection path the gateway exists to close.
"""

from __future__ import annotations

import pytest

from mcp_gateway.config import ServerConfig
from mcp_gateway.session import (
    DownstreamPool,
    DownstreamServer,
    UnsupportedDownstreamRequest,
    _is_input_required_refusal,
)

# ---------------------------------------------------------------------------
# channel 1: legacy sampling/*
# ---------------------------------------------------------------------------

def test_no_sampling_callback_is_installed():
    """Installing one is what ADVERTISES the capability.

    The SDK builds its capability ad by comparing the callback against its own
    default, so any callback of ours -- including one written to refuse -- makes
    the client announce to every downstream server that sampling is available.
    A gateway that refuses sampling should not first invite it.

    Checked on the AST rather than the source text: a docstring mentioning the
    keyword would satisfy a substring search while the call passed one anyway.
    """
    kwargs = _keywords_of_call(DownstreamPool.connect, "ClientSession")
    assert "sampling_callback" not in kwargs, (
        f"ClientSession is constructed with sampling_callback="
        f"{kwargs.get('sampling_callback')}; that makes the client advertise the "
        f"sampling capability to every downstream server"
    )


@pytest.mark.asyncio
async def test_the_gateway_wiring_advertises_no_sampling_capability():
    """The invariant itself, on a real session built the way production builds it.

    Not a proxy for the behaviour: this asks the SDK to produce the capability
    ad it would put on the wire.
    """
    import anyio
    from mcp.client.session import LATEST_HANDSHAKE_VERSION, ClientSession

    _, read  = anyio.create_memory_object_stream(1)
    write, _ = anyio.create_memory_object_stream(1)

    session = ClientSession(read, write)
    assert session._build_capabilities(LATEST_HANDSHAKE_VERSION).sampling is None, (
        "the client advertises sampling; a downstream server will be told the "
        "capability is available and may ask for it"
    )


@pytest.mark.asyncio
async def test_a_custom_callback_would_advertise_it():
    """Pins WHY the callback was removed rather than kept and made to refuse.

    If a future SDK stopped advertising on a custom callback this would fail,
    and the removal could be revisited as a deliberate choice rather than
    carried forward as folklore.
    """
    import anyio
    from mcp.client.session import LATEST_HANDSHAKE_VERSION, ClientSession

    async def _refusing(context, params):  # pragma: no cover - never invoked
        raise AssertionError("not invoked")

    _, read  = anyio.create_memory_object_stream(1)
    write, _ = anyio.create_memory_object_stream(1)

    session = ClientSession(read, write, sampling_callback=_refusing)
    assert session._build_capabilities(LATEST_HANDSHAKE_VERSION).sampling is not None


@pytest.mark.asyncio
async def test_the_sdk_default_declines_rather_than_serving():
    """Not passing a callback must mean DECLINED, never handled.

    The security property does not rest on a callback of ours, so it rests on
    this: the SDK's own default answers a sampling request with an error. A
    future SDK whose default served the request would open the channel with no
    change here, which is why the startup probe also pins the parameter default.
    """
    from mcp import types
    from mcp.client.session import _default_sampling_callback

    answer = await _default_sampling_callback(None, None)

    assert isinstance(answer, types.ErrorData), (
        f"the SDK default no longer declines sampling; it returned {answer!r}"
    )
    assert answer.code == types.INVALID_REQUEST


# ---------------------------------------------------------------------------
# channel 2: InputRequiredResult at 2026-07-28
# ---------------------------------------------------------------------------

def test_the_matcher_recognises_the_sdk_error_it_was_written_for():
    """Tie the matcher to the SDK's OWN error factory.

    The guard is signalled by a plain RuntimeError with no dedicated type, so the
    gateway matches on its message. That is only safe while the message is the
    one this was written against -- hence asserting against the factory rather
    than against a string copied into the test.
    """
    from mcp.client.session import _input_required_unexpected

    for method in ("call_tool", "read_resource"):
        error = _input_required_unexpected(method)
        assert _is_input_required_refusal(error), (
            f"the SDK's input-required error for {method} is no longer "
            f"recognised: {error}. The refusal branch has become dead code and "
            f"the channel would surface as an unhandled error instead."
        )


def test_the_matcher_does_not_claim_unrelated_runtime_errors():
    """A false positive would report an ordinary failure as a refused channel,
    misleading anyone reading the audit trail."""
    for unrelated in (
        RuntimeError("connection reset"),
        RuntimeError("input stream closed"),
        RuntimeError("required argument missing"),
    ):
        assert not _is_input_required_refusal(unrelated), unrelated


@pytest.mark.asyncio
async def test_an_input_required_result_becomes_a_refusal():
    """End to end through the pool: the SDK raises, the gateway refuses.

    Asserted on the code path the gateway actually uses, not on the SDK default
    in isolation -- a default is only worth something on the path that runs.
    """
    from mcp.client.session import _input_required_unexpected

    class _Session:
        async def call_tool(self, name, arguments, read_timeout_seconds=None):
            raise _input_required_unexpected("call_tool")

    pool   = DownstreamPool()
    server = DownstreamServer(
        config  = ServerConfig(name="srv", command=("echo",)),
        session = _Session(),
    )

    with pytest.raises(UnsupportedDownstreamRequest, match="asked the client for input"):
        await pool.call_tool(server, "some_tool", {})


@pytest.mark.asyncio
async def test_an_unrelated_runtime_error_is_not_disguised_as_a_refusal():
    """It must propagate as itself, so a real fault is not filed as a policy
    refusal."""
    class _Session:
        async def call_tool(self, name, arguments, read_timeout_seconds=None):
            raise RuntimeError("downstream pipe broke")

    pool   = DownstreamPool()
    server = DownstreamServer(
        config  = ServerConfig(name="srv", command=("echo",)),
        session = _Session(),
    )

    with pytest.raises(RuntimeError, match="downstream pipe broke"):
        await pool.call_tool(server, "some_tool", {})


def test_the_call_path_does_not_opt_into_input_required():
    """`allow_input_required=True` anywhere in the call path would open the
    channel without any scanning behind it.

    Inspects the AST, not the source text. The first version of this test grepped
    the source and failed on its own docstring, which is the same mistake in the
    other direction: prose is not behaviour.
    """
    kwargs = _keywords_of_call(DownstreamPool.call_tool, "call_tool")
    assert "allow_input_required" not in kwargs, (
        f"the call path sets allow_input_required={kwargs.get('allow_input_required')}; "
        f"opting in requires scanning input_requests first (server-authored "
        f"system_prompt, messages, and the elicitation url)"
    )


def _keywords_of_call(func, callee_suffix: str) -> dict[str, str]:
    """Keyword names and their source text for a call inside `func`.

    Matches the callee by the last component of its dotted name, so both
    `ClientSession(...)` and `server.session.call_tool(...)` are reachable.
    """
    import ast
    import inspect
    import textwrap

    tree  = ast.parse(textwrap.dedent(inspect.getsource(func)))
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        name   = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
        if name != callee_suffix:
            continue
        for kw in node.keywords:
            if kw.arg:
                found[kw.arg] = ast.unparse(kw.value)
    return found
