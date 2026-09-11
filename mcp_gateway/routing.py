# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Which downstream server answers a tool call.

THE EXPOSED NAME IS NEVER PARSED. It is built here as a unique key and resolved
by exact lookup. That is the whole design, and it exists because a downstream
tool name is unconstrained:

  * MCP tool names permit underscore, so `__` is legal INSIDE a tool name;
  * the SDK's charset rule is advisory -- it logs a warning, discards the result,
    and is applied only to locally registered tools, never to names arriving from
    a downstream `tools/list`;
  * the `Tool.name` type is a bare string with no pattern and no length limit.

So a downstream server may publish `evil__tool`, `a/b c`, a 300-character name,
or `filesystem__read_file` -- a name that impersonates another configured
server's namespace. Splitting the exposed name on `__` to find a server would
hand that server a way to be mistaken for another one.

Building a key is safe; interpreting one is not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from mcp_gateway.config import (
    MAX_TOOL_NAME_LENGTH,
    NAMESPACE_SEPARATOR,
    GatewayConfig,
)

# The composed name the gateway publishes should conform to the MCP tool-name
# rules even though the SDK will not enforce them for us.
_CONFORMING_TOOL_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

SessionT = TypeVar("SessionT")


class RoutingError(RuntimeError):
    """The routing table cannot be built as configured."""


@dataclass(frozen=True)
class RouteEntry(Generic[SessionT]):
    """Where an exposed tool actually lives.

    `original_name` is what the downstream server published. The gateway calls
    downstream with THAT, never with the namespaced form, so the namespace never
    leaves this process.
    """

    server_name:   str
    original_name: str
    session:       SessionT
    definition:    Any


@dataclass(frozen=True)
class RejectedTool:
    """A downstream tool the gateway will not publish, and why.

    Rejections are surfaced rather than dropped: an operator needs to know a tool
    is missing, and the security record needs to show that the gateway chose not
    to expose it.
    """

    server_name: str
    raw_name:    str
    reason:      str


def exposed_name(server_name: str, tool_name: str) -> str:
    """The name the agent sees. A presentation and lookup key, nothing more."""
    return f"{server_name}{NAMESPACE_SEPARATOR}{tool_name}"


class RoutingTable(Generic[SessionT]):
    """Exposed tool name -> the server, original name and session behind it."""

    def __init__(self) -> None:
        self._routes:   dict[str, RouteEntry[SessionT]] = {}
        self._rejected: list[RejectedTool] = []

    # -- construction ------------------------------------------------------

    def add_server(self, server_name: str, session: SessionT, tools: list[Any]) -> None:
        """Register one downstream server's tools.

        A tool whose composed name would be malformed, over-length, or already
        taken is REJECTED rather than renamed, truncated or escaped. Truncation
        manufactures collisions, and a reversible encoding over an unvalidated
        attacker-controlled string is a parser -- the thing this module exists to
        avoid.
        """
        for tool in tools:
            raw = getattr(tool, "name", None)
            if not isinstance(raw, str) or not raw:
                self._rejected.append(RejectedTool(server_name, repr(raw), "name is not a string"))
                continue

            composed = exposed_name(server_name, raw)

            if len(composed) > MAX_TOOL_NAME_LENGTH:
                self._rejected.append(RejectedTool(
                    server_name, raw,
                    f"composed name is {len(composed)} characters, over the "
                    f"{MAX_TOOL_NAME_LENGTH}-character limit",
                ))
                continue

            if not _CONFORMING_TOOL_NAME.match(composed):
                self._rejected.append(RejectedTool(
                    server_name, raw,
                    "composed name contains characters outside the permitted set",
                ))
                continue

            if composed in self._routes:
                # Reached when two servers publish names that compose to the same
                # key. Server names are unique, so this needs a downstream name
                # crafted to collide -- exactly the case that must not resolve to
                # a guess.
                existing = self._routes[composed]
                self._rejected.append(RejectedTool(
                    server_name, raw,
                    f"composed name {composed!r} is already published by server "
                    f"{existing.server_name!r}",
                ))
                continue

            self._routes[composed] = RouteEntry(
                server_name   = server_name,
                original_name = raw,
                session       = session,
                definition    = tool,
            )

    # -- resolution --------------------------------------------------------

    def resolve(self, name: str) -> RouteEntry[SessionT] | None:
        """Exact lookup. A miss is a miss.

        No prefix stripping, no substring match, no search across servers. An
        unresolved tool is refused by the caller; it is never approximated.
        """
        return self._routes.get(name)

    def exposed_names(self) -> list[str]:
        return list(self._routes)

    def entries(self) -> list[tuple[str, RouteEntry[SessionT]]]:
        """Every (exposed name, route) pair, for startup checks and reporting."""
        return list(self._routes.items())

    @property
    def rejected(self) -> tuple[RejectedTool, ...]:
        return tuple(self._rejected)

    def __len__(self) -> int:
        return len(self._routes)


def assert_no_cross_server_shadowing(table: RoutingTable[Any], config: GatewayConfig) -> None:
    """Refuse to start if a published name could be READ as another server's.

    A PRESENTATION DEFENCE, not a routing mechanism. Routing is unaffected by
    what a tool is called: it is an exact lookup in the structured map, and a
    name crafted to resemble another namespace still resolves to the server that
    published it. That property is tested separately and does not depend on this
    check.

    What this defends is the tool list a human or an agent reads. A downstream
    server configured as `evil` can publish a tool literally named
    `filesystem__read_file`, which composes to `evil__filesystem__read_file`. It
    routes correctly, but it READS as though it belongs to `filesystem`, and an
    operator auditing the list or approving a call should not have to know that
    only the first separator counts.

    Compared against EVERY other configured server identity, from the full set,
    so the outcome does not depend on the order servers were registered in.

    NOT CONFIGURABLE. An opt-out is a setting an attacker would like enabled, and
    the condition it suppresses is one an operator cannot see by reading the tool
    list -- which is the whole reason the check exists.
    """
    configured = {server.name for server in config.servers}

    for _exposed, entry in table.entries():
        if NAMESPACE_SEPARATOR not in entry.original_name:
            continue
        claimed = entry.original_name.split(NAMESPACE_SEPARATOR, 1)[0]
        if claimed in configured and claimed != entry.server_name:
            raise RoutingError(
                f"server {entry.server_name!r} publishes a tool named "
                f"{entry.original_name!r}, which reads as belonging to the "
                f"configured server {claimed!r}. Refusing to start: a tool list "
                f"that misattributes a tool is a shadowing surface, even though "
                f"routing itself resolves correctly."
            )
