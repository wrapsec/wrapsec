# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The only module that touches the MCP package's API.

Everything else in the gateway works on the plain types defined here, so the
enforcement code is testable without the MCP package installed and an SDK change
is one module's problem rather than a sweep through the security layer.

WHY THE SEAM IS NARROW. The gateway builds against the low-level server, and
parts of that surface are provisional: the middleware seam carries a note in the
SDK itself that its signature may change in a 2.x MINOR release. The package is
pinned exactly for that reason, and this module is where a break surfaces.

WHY THE VERSION IS CHECKED AT STARTUP. A missing or changed API must never be
handled by skipping the affected control. A gateway that starts with an
enforcement path quietly disabled is worse than one that refuses to start: the
agent keeps working and nobody learns that enforcement stopped.
"""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass
from typing import Any

# The version this gateway was written and verified against. Raising it is a
# deliberate compatibility change, not an incidental bump: see requirements-mcp.txt.
SUPPORTED_MCP_VERSION = "2.2.0"


class UnsupportedMCPPackage(RuntimeError):
    """The installed MCP package cannot be used safely.

    Raised at startup, before anything is served. Carrying on with a partially
    recognised SDK would mean guessing which controls still work.
    """


@dataclass(frozen=True)
class ToolDefinition:
    """One downstream tool, in gateway terms rather than MCP terms.

    `name` is the name the downstream server published, verbatim. It is
    UNVALIDATED and attacker-influenceable: the MCP type declares it as a plain
    string with no pattern and no length limit, and the SDK's own tool-name rules
    are advisory and applied only to locally registered tools. Treat it as data.
    """

    name:         str
    title:        str | None
    description:  str | None
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCallOutcome:
    """A downstream tool result reduced to what the gateway acts on."""

    text_parts: tuple[str, ...]
    is_error:   bool
    raw:        Any          # the original result, forwarded when allowed


def installed_mcp_version() -> str:
    return importlib.metadata.version("mcp")


def verify_mcp_package() -> None:
    """Fail closed unless the installed MCP package is the one we support.

    A version mismatch alone is a warning, not a refusal: an operator may have a
    good reason, and the APIs may well be identical. A MISSING OR CHANGED API is
    a refusal, because that is the case where a control silently stops working.
    """
    import logging

    logger  = logging.getLogger(__name__)
    version = installed_mcp_version()

    missing = _missing_apis()
    if missing:
        raise UnsupportedMCPPackage(
            f"the installed MCP package ({version}) does not expose the APIs this "
            f"gateway depends on: {', '.join(missing)}. Expected {SUPPORTED_MCP_VERSION}. "
            f"Refusing to start rather than running with an enforcement path disabled."
        )

    if version != SUPPORTED_MCP_VERSION:
        logger.warning(
            "MCP package %s is installed but this gateway is verified against %s; "
            "the APIs it depends on are present, so it is starting, but this "
            "combination is untested",
            version, SUPPORTED_MCP_VERSION,
        )


def _missing_apis() -> list[str]:
    """Name every API the gateway relies on that is absent or the wrong shape.

    Checked by probing rather than by comparing version strings, so an SDK that
    moved an API is caught even at the expected version.
    """
    import inspect

    missing: list[str] = []

    try:
        from mcp.server.lowlevel import Server
    except Exception:
        return ["mcp.server.lowlevel.Server"]

    init = inspect.signature(Server.__init__).parameters
    for hook in ("on_list_tools", "on_call_tool"):
        if hook not in init:
            missing.append(f"Server.__init__({hook}=...)")
    if not hasattr(Server, "add_request_handler"):
        missing.append("Server.add_request_handler")

    try:
        from mcp.client.session import ClientSession

        call_tool = inspect.signature(ClientSession.call_tool).parameters
        # The guard that keeps the modern sampling/elicitation channel closed.
        # Its ABSENCE would mean an InputRequiredResult is returned rather than
        # refused, which is a silent widening of what reaches the agent.
        if "allow_input_required" not in call_tool:
            missing.append("ClientSession.call_tool(allow_input_required=...)")
        elif call_tool["allow_input_required"].default is not False:
            missing.append(
                "ClientSession.call_tool(allow_input_required=) no longer defaults to False"
            )
        if "sampling_callback" not in inspect.signature(ClientSession.__init__).parameters:
            missing.append("ClientSession(sampling_callback=...)")
    except Exception:
        missing.append("mcp.client.session.ClientSession")

    try:
        from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: F401
    except Exception:
        missing.append("mcp.client.stdio")

    try:
        from mcp.server.stdio import stdio_server  # noqa: F401
    except Exception:
        missing.append("mcp.server.stdio.stdio_server")

    return missing


def to_tool_definition(tool: Any) -> ToolDefinition:
    """Convert an MCP `Tool` into gateway terms."""
    return ToolDefinition(
        name         = tool.name,
        title        = getattr(tool, "title", None),
        description  = getattr(tool, "description", None),
        input_schema = getattr(tool, "input_schema", None) or {},
    )


def text_parts_of(result: Any) -> tuple[str, ...]:
    """Every textual part of a tool result, in order.

    Non-text content (images, binary, embedded resources) is NOT rendered into
    text. V1 does not scan it, and inventing a textual stand-in would mean
    scanning something the agent never receives while forwarding something that
    was never scanned. Such parts are simply not returned here; the caller
    forwards them unchanged and the plan records that limit.
    """
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return tuple(parts)
