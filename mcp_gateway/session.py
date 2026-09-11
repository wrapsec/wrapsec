# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Connections to the downstream MCP servers.

Owns the client side: spawn each configured server, initialize, list its tools,
and call them. It makes no security decision. What it DOES do is refuse to open
channels the gateway has not been built to inspect, because a channel that is
open by default is a channel nobody decided to open.

TWO REFUSALS ARE WIRED IN HERE, not bolted on later:

1. `sampling_callback` -- on legacy protocol revisions a downstream server can
   ask the client to run an inference. The gateway supplies a callback that
   refuses, so the request is answered rather than served.

2. `allow_input_required` stays at its default of False -- at protocol revision
   2026-07-28 the server-initiated channel is gone and the same asks arrive
   inside a tool result as an `InputRequiredResult`. With the flag False the SDK
   raises instead of returning it, which this module turns into a refusal.

Both are refusals of content the gateway cannot yet inspect. Opening either one
is a security change that has to come with scanning, not a flag flip.

WHICH PROTOCOL REVISION, AND WHY IT MATTERS HERE. Downstream connections use the
client session's handshake, which negotiates 2025-11-25. An input-required
result is only a valid answer to a tool call at 2026-07-28, so on these
connections that channel is closed BY CONSTRUCTION rather than by the guard: a
server attempting it produces a response the client will not deserialize.

The `allow_input_required` guard is therefore defence in depth for this build,
not the control doing the work. It is kept, and kept tested, because the
negotiated revision is a property of the SDK rather than a decision expressed
here, and a future version that negotiates higher would make the channel
reachable with no other change. A test pins the property so that shift is
visible rather than silent.
"""

from __future__ import annotations

import logging
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from mcp_gateway.config import ServerConfig

logger = logging.getLogger(__name__)


class DownstreamUnavailable(RuntimeError):
    """A configured downstream server could not be reached or initialized."""


class UnusableDownstreamResponse(RuntimeError):
    """The downstream server answered with something the client cannot read.

    A malformed result, or one whose shape the negotiated protocol revision does
    not allow. Distinguished from a server being unreachable because they are
    different signals: one says the network failed, the other says the server is
    sending things this gateway rejects, which is what a compromised or
    misbehaving server looks like.
    """


class UnsupportedDownstreamRequest(RuntimeError):
    """The downstream server asked for something V1 refuses to serve.

    Covers both sampling channels. Raised rather than returned so no caller can
    mistake it for a result.
    """


@dataclass
class DownstreamServer:
    """One live connection, paired with the config that named it."""

    config:  ServerConfig
    session: Any

    @property
    def name(self) -> str:
        return self.config.name


async def _refuse_sampling(*args: Any, **kwargs: Any) -> Any:
    """Answer a legacy `sampling/*` request with a refusal.

    V1 does not inspect sampling, so it does not serve it. The alternative --
    forwarding to the agent's model -- would hand a downstream server a way to
    run inference with content the gateway never scanned.
    """
    raise UnsupportedDownstreamRequest(
        "sampling is not available through this gateway"
    )


class DownstreamPool:
    """Every configured downstream server, connected for the process lifetime.

    One pool per gateway process, matching the runtime model: stdio is one client
    per process, so there is exactly one pool and it is not shared.
    """

    def __init__(self) -> None:
        self._stack   = AsyncExitStack()
        self._servers: dict[str, DownstreamServer] = {}

    async def connect(self, config: ServerConfig) -> DownstreamServer:
        """Spawn and initialize one downstream server."""
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        params = StdioServerParameters(
            command = config.command[0],
            args    = list(config.command[1:]),
            env     = dict(config.env) or None,
            cwd     = config.cwd,
        )

        try:
            read, write = await self._stack.enter_async_context(stdio_client(params))
            session = await self._stack.enter_async_context(
                ClientSession(read, write, sampling_callback=_refuse_sampling)
            )
            await session.initialize()
        except Exception as exc:
            # Reported as unavailable rather than swallowed: the gateway cannot
            # serve a server it could not start, and pretending otherwise would
            # surface later as an unresolved tool with no explanation.
            raise DownstreamUnavailable(
                f"downstream server {config.name!r} could not be started: {exc}"
            ) from exc

        server = DownstreamServer(config=config, session=session)
        self._servers[config.name] = server
        return server

    async def list_tools(self, server: DownstreamServer) -> list[Any]:
        """The tools one downstream server publishes, unmodified.

        Names are returned exactly as received. They are unvalidated and
        attacker-influenceable; normalizing them here would hide from the routing
        layer what the server actually said.
        """
        result = await server.session.list_tools()
        return list(result.tools)

    async def call_tool(
        self,
        server:    DownstreamServer,
        tool_name: str,
        arguments: dict[str, Any] | None,
    ) -> Any:
        """Invoke a tool with the name the downstream server published.

        `allow_input_required` is left at its default. The SDK then raises when a
        server returns an `InputRequiredResult`, and that is converted here into
        the same refusal as a legacy sampling request: a downstream server must
        not reach the agent through a channel V1 does not scan.
        """
        try:
            return await server.session.call_tool(tool_name, arguments or {})
        except ValidationError as exc:
            # The server answered with a shape the client will not accept. On
            # this build that includes an input-required result, which the
            # negotiated revision does not permit -- see the note on revisions
            # below. Converted into a refusal rather than allowed to escape,
            # because a protocol fault reaching the agent is a fault it will
            # commonly retry, and the refusal contract says a blocked operation
            # comes back as a valid result telling it not to.
            logger.warning(
                "downstream server %s returned an unusable response for tool %s: %s",
                server.name, tool_name, str(exc)[:200],
            )
            raise UnusableDownstreamResponse(
                "the tool returned a response this gateway could not use"
            ) from exc
        except RuntimeError as exc:
            if _is_input_required_refusal(exc):
                logger.warning(
                    "downstream server %s returned an input-required result for "
                    "tool %s; refusing (V1 does not inspect that channel)",
                    server.name, tool_name,
                )
                raise UnsupportedDownstreamRequest(
                    "the tool asked the client for input, which is not available "
                    "through this gateway"
                ) from exc
            raise

    async def aclose(self) -> None:
        await self._stack.aclose()
        self._servers.clear()

    def __len__(self) -> int:
        return len(self._servers)


# The SDK signals its input-required guard with a plain `RuntimeError` built by
# `mcp.client.session._input_required_unexpected`, whose message names the result
# type and the flag. There is no dedicated exception type to catch, so these two
# markers identify it; both appear in the SDK's message and neither is a phrase an
# unrelated RuntimeError is likely to carry.
#
# A test asserts these markers against the SDK's OWN error factory, so a message
# change fails the suite rather than silently turning this branch into dead code.
_INPUT_REQUIRED_MARKERS = ("inputrequiredresult", "allow_input_required")


def _is_input_required_refusal(exc: BaseException) -> bool:
    """Whether a RuntimeError is the SDK's input-required guard firing.

    Deliberately narrow. A false negative re-raises the original error, which
    still fails the call closed; a false positive would report an unrelated
    failure as a refused channel, which would mislead an operator reading the
    audit trail.
    """
    text = str(exc).lower()
    return all(marker in text for marker in _INPUT_REQUIRED_MARKERS)
