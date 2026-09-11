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
    _refuse_sampling,
)

# ---------------------------------------------------------------------------
# channel 1: legacy sampling/*
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_sampling_request_is_refused_not_served():
    """The callback the gateway installs must refuse, whatever it is handed."""
    with pytest.raises(UnsupportedDownstreamRequest, match="sampling"):
        await _refuse_sampling(object(), object())


def test_the_sampling_callback_is_installed_on_every_connection():
    """A connection opened without the callback would let the SDK's own default
    handling apply, which is not the gateway's decision to delegate.

    Checked on the AST rather than on the source text: a docstring or comment
    mentioning the keyword would satisfy a substring search while the call itself
    passed nothing.
    """
    kwargs = _keywords_of_call(DownstreamPool.connect, "ClientSession")
    assert "sampling_callback" in kwargs, (
        "ClientSession is constructed without sampling_callback; a downstream "
        "server could reach the agent's model"
    )
    assert kwargs["sampling_callback"] == "_refuse_sampling", (
        f"sampling_callback is {kwargs['sampling_callback']}, not the refusing "
        f"callback"
    )


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
        async def call_tool(self, name, arguments):
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
        async def call_tool(self, name, arguments):
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
