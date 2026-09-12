# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The contract every security interceptor implements.

Three decision points, matching the three boundaries the gateway protects:
tool definitions entering the agent's context, calls and arguments leaving it,
and results coming back.

Each hook works on gateway types and plain values. None of them import `mcp.*`:
the security logic must stay testable without the MCP package, and an SDK change
must not reach into it.
"""

from __future__ import annotations

from typing import Any, Protocol

from mcp_gateway.decision import Refusal


class Interceptor(Protocol):
    """What the proxy consults. Implementations decide; the proxy obeys.

    Every hook is awaitable. A security decision here means calling the WrapSec
    API, so a synchronous seam would force each implementation to block the event
    loop while a scan is in flight -- and one stalled scan would stall every
    other request the process is serving.
    """

    async def on_tool_definition(
        self, *, server_name: str, definition: Any, trace_id: str | None = None,
        turn_index: int | None = None,
    ) -> Any | None:
        """Return the definition to publish, or None to withhold it."""
        ...

    async def on_tool_call(
        self,
        *,
        server_name:   str,
        original_name: str,
        exposed_name:  str,
        arguments:     dict[str, Any],
        trace_id:      str,
        turn_index:    int | None = None,
    ) -> Refusal | None:
        """Return a Refusal to block the call, or None to allow it."""
        ...

    async def on_tool_result(
        self, *, server_name: str, result: Any, trace_id: str,
        turn_index: int | None = None,
    ) -> Any:
        """Return the result to deliver, or a Refusal to block it."""
        ...


class PassThrough:
    """Inspects nothing and allows everything.

    DEVELOPMENT AND TEST INFRASTRUCTURE ONLY. It exists so the protocol skeleton
    can be built and exercised before the detection phases land, and so tests can
    isolate protocol behaviour from detection behaviour.

    It is not a production configuration and must not become one: a gateway
    running this is indistinguishable from a working one from the outside, since
    nothing is blocked because nothing is examined. `Gateway.require_enforcement`
    is what refuses it outside development.
    """

    async def on_tool_definition(
        self, *, server_name: str, definition: Any, trace_id: str | None = None,
        turn_index: int | None = None,
    ) -> Any | None:
        return definition

    async def on_tool_call(self, **kwargs: Any) -> Refusal | None:
        return None

    async def on_tool_result(self, **kwargs: Any) -> Any:
        return kwargs.get("result")
