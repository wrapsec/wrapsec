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
        # Both guards that keep a server-initiated ask channel closed. Their
        # ABSENCE, or a default flipped to True, would mean the SDK RETURNS what
        # it currently refuses -- a silent widening of what reaches the agent,
        # with no scanning behind it and no other code change to notice.
        #
        # Enumerated rather than checked one at a time: the claimed-result
        # channel was missed once precisely because only the first was pinned.
        for guard in ("allow_input_required", "allow_claimed"):
            if guard not in call_tool:
                missing.append(f"ClientSession.call_tool({guard}=...)")
            elif call_tool[guard].default is not False:
                missing.append(
                    f"ClientSession.call_tool({guard}=) no longer defaults to False"
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
    """Every part of a result that a model will read as text, in order.

    Text reaches the agent through more than one block type, and scanning only
    the obvious one leaves the rest unexamined:

      * a text block, the usual case;
      * a resource LINK, whose name, title and description are prose the model
        reads, and whose uri is a destination it may be induced to follow;
      * an EMBEDDED resource, whose contents may be text.

    A link's uri is included deliberately. It is not prose, but it is
    attacker-chosen and it is the payload in an exfiltration or phishing lure, so
    it belongs in what gets judged rather than passing as metadata.

    STRUCTURED CONTENT IS INCLUDED. A result may carry `structured_content`
    alongside its blocks, and a server is free to return the blocks EMPTY and put
    everything there -- measured against this MCP version, the client accepts
    that and the value is preserved end to end. Scanning only the blocks would
    therefore leave a one-step bypass: put the payload in the structured field
    and nothing is examined.

    It is rendered with the same call the MCP package itself uses when mirroring
    a tool's structured return into the model-facing text block, so what the
    detector reads is the representation the protocol already produces rather
    than a second one invented here.

    NOT INCLUDED: binary payloads (image, audio, blob), which this build does not
    scan. That is a limit of this build, not a statement that they are safe.
    """
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        parts.extend(_block_text(block))

    structured = getattr(result, "structured_content", None)
    if structured is not None:
        parts.append(structured_text(structured))
    return tuple(parts)


def structured_text(structured: Any) -> str:
    """`structured_content` rendered exactly as the MCP package renders it.

    The same call the package uses to turn a tool's structured return into the
    text block a model reads. Matching it means the detector is judging the
    representation the protocol produces, not an approximation of it, and a
    payload that appears in both places is judged identically in both.

    `fallback=str` so a value the serializer does not know how to encode still
    reaches the detector as text instead of raising and losing the content.
    """
    import pydantic_core

    return pydantic_core.to_json(structured, fallback=str, indent=2).decode()


def _block_text(block: Any) -> list[str]:
    """The readable text of one content block."""
    found: list[str] = []

    text = getattr(block, "text", None)
    if isinstance(text, str) and text:
        found.append(text)

    # A resource link: prose plus the destination it points at.
    for attr in ("name", "title", "description", "uri"):
        value = getattr(block, attr, None)
        if isinstance(value, str) and value:
            found.append(value)
        elif value is not None and attr == "uri":
            # A uri may arrive as a parsed type rather than a string; it is still
            # the destination, so it is judged rather than skipped.
            rendered = str(value)
            if rendered:
                found.append(rendered)

    # An embedded resource wraps its own contents, which may be text.
    resource = getattr(block, "resource", None)
    if resource is not None:
        inner = getattr(resource, "text", None)
        if isinstance(inner, str) and inner:
            found.append(inner)
        uri = getattr(resource, "uri", None)
        if uri is not None and str(uri):
            found.append(str(uri))

    return found
