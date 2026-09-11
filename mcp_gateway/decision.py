# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Turning a refusal into something an MCP client can actually receive.

A blocked operation must come back as a VALID MCP result, not as a crash and not
as a transport error. An agent that receives a protocol fault will often retry,
and a retry loop against a security control is indistinguishable from an attack
on it.

THE RULES, and why each one is here:

  * never echo the blocked content -- the refusal is delivered into the same
    context the content was going to reach, so quoting it to explain the block
    would complete the injection the block prevented;
  * carry a correlation identifier -- an operator has to be able to find the
    decision behind a refusal, and the agent cannot be trusted to report it;
  * tell the agent not to retry -- a model that reads "blocked" without that
    instruction frequently tries a reworded call, which is exactly the behaviour
    a prompt-injection payload wants;
  * say nothing about detector internals -- scores, layer names and matched
    patterns are an oracle for tuning an evasion, and they belong in the audit
    record, not in the agent's context.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Refusal:
    """A refused operation, in gateway terms.

    `reason` is a vocabulary value for the audit trail. `detail` is for the
    operator-facing record ONLY and is never rendered into the agent's copy.
    """

    reason:   str
    trace_id: str
    detail:   str | None = None


# The vocabulary. Kept small and explicit: a reason that does not appear here
# cannot reach an audit record, so a new refusal has to be named deliberately.
TOOL_NOT_RESOLVED        = "TOOL_NOT_RESOLVED"
TOOL_DENIED_BY_POLICY    = "TOOL_DENIED_BY_POLICY"
UNSUPPORTED_SERVER_REQUEST = "UNSUPPORTED_MCP_SERVER_REQUEST"
DOWNSTREAM_UNAVAILABLE   = "DOWNSTREAM_UNAVAILABLE"
SYSTEM_ERROR             = "SYSTEM_ERROR"

_AGENT_MESSAGES = {
    TOOL_NOT_RESOLVED:
        "The requested tool is not available through this gateway.",
    TOOL_DENIED_BY_POLICY:
        "This tool is not permitted by security policy.",
    UNSUPPORTED_SERVER_REQUEST:
        "The tool attempted an operation this gateway does not support.",
    DOWNSTREAM_UNAVAILABLE:
        "The tool could not be reached.",
    SYSTEM_ERROR:
        "The operation was refused because a security check could not run.",
}

_DO_NOT_RETRY = "Do not retry this operation."


def refusal_text(refusal: Refusal) -> str:
    """The text an agent receives. Fixed phrasing, no content, no internals."""
    message = _AGENT_MESSAGES.get(refusal.reason, _AGENT_MESSAGES[SYSTEM_ERROR])
    return f"[WrapSec] {message} Trace: {refusal.trace_id}. {_DO_NOT_RETRY}"


def refusal_result(refusal: Refusal) -> Any:
    """The refusal as an MCP `CallToolResult` with `is_error` set.

    `is_error` rather than a protocol-level error: the call reached the gateway
    and was answered, so this is a tool outcome, not a transport failure. Clients
    surface it to the model instead of treating the connection as broken.
    """
    from mcp import types

    return types.CallToolResult(
        content  = [types.TextContent(type="text", text=refusal_text(refusal))],
        is_error = True,
    )
