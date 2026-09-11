# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The MCP surface the agent talks to.

Protocol handling and coordination only. It holds no detection logic: security
decisions belong to the interceptors, and this module's job is to make sure they
are consulted and that whatever they return is honoured.

WHAT PHASE 1 DELIBERATELY DOES NOT DO. The interceptor seam exists here and is
called on every path, but Phase 1 ships only a pass-through implementation, so
the gateway is a transparent proxy and nothing is scanned yet. That mode is
DEVELOPMENT AND TEST INFRASTRUCTURE. It is not a supported production
configuration, and `require_enforcement()` is what stops it becoming one by
accident.

The seam is built first, rather than added once the protocol works, because
retrofitting an interception point into a working proxy is how a path ends up
forwarding without passing through it.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_gateway import decision
from mcp_gateway.config import GatewayConfig
from mcp_gateway.interceptors.base import Interceptor, PassThrough
from mcp_gateway.routing import RoutingTable, exposed_name
from mcp_gateway.session import (
    DownstreamPool,
    DownstreamUnavailable,
    UnsupportedDownstreamRequest,
)

logger = logging.getLogger(__name__)


class EnforcementDisabled(RuntimeError):
    """Refusing to serve without security interception outside development."""


class Gateway:
    """One agent connection, its downstream servers, and its routing table."""

    def __init__(
        self,
        config:      GatewayConfig,
        pool:        DownstreamPool,
        interceptor: Interceptor | None = None,
        *,
        trace_source: Any = None,
    ) -> None:
        self._config      = config
        self._pool        = pool
        self._routes: RoutingTable[Any] = RoutingTable()
        self._interceptor = interceptor or PassThrough()
        self._trace       = trace_source or _TraceIds()

    # -- startup -----------------------------------------------------------

    def require_enforcement(self, *, environment: str) -> None:
        """Refuse to run a pass-through gateway outside development.

        The protocol-only mode is useful while building and while testing, and it
        is indistinguishable from a working gateway from the outside: tools list,
        calls succeed, nothing is blocked because nothing is inspected. That is
        precisely why it must not be reachable in production by configuration
        alone.
        """
        if isinstance(self._interceptor, PassThrough) and environment != "development":
            raise EnforcementDisabled(
                "the gateway is configured without security interception, which is "
                "development and test infrastructure only. Refusing to start in "
                f"environment {environment!r}."
            )

    async def connect_all(self) -> None:
        """Connect every configured downstream server and build the routing table.

        A server that cannot be started aborts startup. Serving a partial tool
        set would mean an agent silently loses capability, and an operator would
        have no signal beyond a missing tool.
        """
        from mcp_gateway.routing import assert_no_cross_server_shadowing

        for server_config in self._config.servers:
            server = await self._pool.connect(server_config)
            tools  = await self._pool.list_tools(server)
            self._routes.add_server(server_config.name, server, tools)

        for rejected in self._routes.rejected:
            # Surfaced, not dropped: a tool the gateway refused to publish is an
            # operator-visible fact, and the reason matters when a tool is
            # "missing" for no apparent reason.
            logger.warning(
                "not publishing tool %r from server %s: %s",
                rejected.raw_name, rejected.server_name, rejected.reason,
            )

        assert_no_cross_server_shadowing(self._routes, self._config)

    # -- protocol handlers -------------------------------------------------

    async def on_list_tools(self, ctx: Any, params: Any) -> Any:
        """Publish the downstream tools under their namespaced names."""
        from mcp import types

        published = []
        for name, entry in self._routes.entries():
            definition = await self._interceptor.on_tool_definition(
                server_name = entry.server_name,
                definition  = entry.definition,
            )
            if definition is None:
                # The interceptor withheld it. Nothing is said to the agent about
                # why: a tool that is absent is simply absent, and explaining the
                # block here would put the blocked description into the context
                # the block was protecting.
                continue
            published.append(_republish(types, definition, name))

        return types.ListToolsResult(tools=published)

    async def on_call_tool(self, ctx: Any, params: Any) -> Any:
        """Resolve, consult the interceptor, then forward or refuse."""
        trace_id = self._trace.next()
        name     = getattr(params, "name", None) or ""
        args     = getattr(params, "arguments", None) or {}

        entry = self._routes.resolve(name)
        if entry is None:
            # Exact lookup missed. No prefix stripping, no nearest match: an
            # unresolved tool is refused, never approximated onto another server.
            logger.warning("unresolved tool %r (trace %s)", name, trace_id)
            return decision.refusal_result(decision.Refusal(
                reason   = decision.TOOL_NOT_RESOLVED,
                trace_id = trace_id,
                detail   = f"no route for exposed name {name!r}",
            ))

        verdict = await self._interceptor.on_tool_call(
            server_name   = entry.server_name,
            original_name = entry.original_name,
            exposed_name  = name,
            arguments     = args,
            trace_id      = trace_id,
        )
        if verdict is not None:
            return decision.refusal_result(verdict)

        try:
            result = await self._pool.call_tool(entry.session, entry.original_name, args)
        except UnsupportedDownstreamRequest as exc:
            # A refused channel (sampling, or the input-required result that
            # replaced it). Reported as a refusal rather than an error so the
            # agent is told not to retry.
            logger.warning("refused downstream request for %r: %s", name, exc)
            return decision.refusal_result(decision.Refusal(
                reason   = decision.UNSUPPORTED_SERVER_REQUEST,
                trace_id = trace_id,
                detail   = str(exc),
            ))
        except DownstreamUnavailable as exc:
            return decision.refusal_result(decision.Refusal(
                reason   = decision.DOWNSTREAM_UNAVAILABLE,
                trace_id = trace_id,
                detail   = str(exc),
            ))

        inspected = await self._interceptor.on_tool_result(
            server_name = entry.server_name,
            result      = result,
            trace_id    = trace_id,
        )
        if isinstance(inspected, decision.Refusal):
            return decision.refusal_result(inspected)
        return inspected

    # -- wiring ------------------------------------------------------------

    def build_server(self) -> Any:
        """The low-level MCP server, with this gateway's handlers bound.

        Only the two methods V1 inspects are registered. Every other method is
        answered `METHOD_NOT_FOUND` by the runner rather than relayed: there is
        no catch-all handler, and forwarding an uninspected method to a
        downstream server is not a default this plan takes.
        """
        from mcp.server.lowlevel import Server

        return Server(
            "wrapsec-mcp-gateway",
            on_list_tools = self.on_list_tools,
            on_call_tool  = self.on_call_tool,
        )

    @property
    def routes(self) -> RoutingTable[Any]:
        return self._routes


def _republish(types: Any, definition: Any, published_name: str) -> Any:
    """The downstream definition, under the name the gateway publishes.

    A copy is made rather than mutating the object the downstream server handed
    over, so the original name stays available for routing and for the audit
    record.
    """
    return types.Tool(
        name         = published_name,
        title        = getattr(definition, "title", None),
        description  = getattr(definition, "description", None),
        inputSchema  = getattr(definition, "input_schema", None) or {"type": "object"},
    )


class _TraceIds:
    """Per-connection correlation identifiers.

    Gateway-assigned, not taken from the MCP protocol: the 2026-07-28 revision
    has no session, so anything derived from protocol state would work on a
    legacy connection and produce nothing on a modern one.
    """

    def __init__(self) -> None:
        self._n = 0

    def next(self) -> str:
        import uuid

        self._n += 1
        return f"mcp_{uuid.uuid4().hex[:16]}"


__all__ = ["EnforcementDisabled", "Gateway", "exposed_name"]
