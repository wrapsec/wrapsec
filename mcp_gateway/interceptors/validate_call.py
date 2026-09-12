# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Tool calls, checked before they leave for a downstream server.

Two controls, in this order:

  1. POLICY -- is this tool permitted at all;
  2. ARGUMENTS -- is what the agent is sending safe to send.

Policy runs first because it is decisive and free: a denied tool never reaches
the detector, never reaches the network, and never reaches the downstream
server. A refused call is a refusal the agent is told not to retry, not an error.

WHAT THE POLICY MATCHES. The exposed name the agent sent, compared against the
entries as the operator wrote them. Which server's policy applies comes from the
resolved route, not from reading the name apart -- the exposed name is a key, and
this module does not interpret it any more than routing does.

WHAT GETS SCANNED. The whole arguments object, serialised the same way a
structured result is. Arguments nest arbitrarily, so picking out the strings at
the top level would miss a payload one level down, and picking them out
recursively would still miss one placed in a key. Serialising sends structure to
the detector as well, which is noise rather than signal, and that cost is
accepted for coverage that has no gaps to reason about.

NO NETWORK CONTROL IS CLAIMED. A URL in an argument is scanned as text like
anything else. Nothing here decides where a tool may connect: a tool can reach
the network without a URL ever passing through its arguments, so egress belongs
at the network boundary and calling this an egress control would be false.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_gateway.config import NAMESPACE_SEPARATOR, GatewayConfig
from mcp_gateway.decision import TOOL_DENIED_BY_POLICY, Refusal
from mcp_gateway.mcp_compat import structured_text
from mcp_gateway.scanner import SOURCE_TOOL_ARGUMENT, ScannerProtocol

logger = logging.getLogger(__name__)


class ToolCallValidator:
    """Decides whether a call may be forwarded."""

    def __init__(
        self,
        config:  GatewayConfig,
        scanner: ScannerProtocol,
        *,
        scan_arguments: bool = True,
    ) -> None:
        self._config         = config
        self._scanner        = scanner
        self._scan_arguments = scan_arguments

    async def inspect(
        self,
        *,
        server_name:   str,
        original_name: str,
        exposed_name:  str,
        arguments:     dict[str, Any],
        trace_id:      str,
    ) -> Refusal | None:
        """Return a Refusal to block the call, or None to let it through."""
        denied = self._policy_refusal(
            server_name   = server_name,
            original_name = original_name,
            exposed_name  = exposed_name,
            trace_id      = trace_id,
        )
        if denied is not None:
            return denied

        if not self._scan_arguments or not arguments:
            return None

        verdict = await self._scanner.scan(
            structured_text(arguments), source=SOURCE_TOOL_ARGUMENT, trace_id=trace_id,
        )
        if verdict.blocked:
            logger.warning(
                "refusing a call to %s on server %s: %s (trace %s)",
                exposed_name, server_name, verdict.reason, verdict.trace_id,
            )
            return Refusal(
                reason   = verdict.reason,
                trace_id = verdict.trace_id,
                detail   = f"arguments to {exposed_name!r} on server {server_name!r}",
                failed   = verdict.failed,
            )

        # A SANITIZE verdict on arguments is treated as ALLOW. Rewriting what the
        # agent asked for would send the downstream server a call the agent did
        # not make, and the gateway has no way to tell whether the redacted form
        # still means what was intended.
        return None

    def _policy_refusal(
        self, *, server_name: str, original_name: str, exposed_name: str, trace_id: str,
    ) -> Refusal | None:
        server = self._config.by_name(server_name)
        if server is None:
            # The route named a server the configuration does not have. Refused
            # rather than defaulted: there is no policy to apply.
            return Refusal(
                reason   = TOOL_DENIED_BY_POLICY,
                trace_id = trace_id,
                detail   = f"no configured server named {server_name!r}",
            )

        policy = server.tools

        if _matches(policy.deny, exposed_name, original_name):
            logger.warning(
                "denied by policy: %s on server %s (trace %s)",
                exposed_name, server_name, trace_id,
            )
            return Refusal(
                reason   = TOOL_DENIED_BY_POLICY,
                trace_id = trace_id,
                detail   = f"{exposed_name!r} is denied on server {server_name!r}",
            )

        # An omitted allow list is no restriction. A PRESENT one is exhaustive:
        # anything not named is refused, so adding a tool downstream does not
        # silently widen what an agent may call.
        if policy.allow and not _matches(policy.allow, exposed_name, original_name):
            logger.warning(
                "not permitted by policy: %s on server %s (trace %s)",
                exposed_name, server_name, trace_id,
            )
            return Refusal(
                reason   = TOOL_DENIED_BY_POLICY,
                trace_id = trace_id,
                detail   = f"{exposed_name!r} is not in the allow list for "
                           f"server {server_name!r}",
            )

        return None


def _matches(entries: tuple[str, ...], exposed_name: str, original_name: str) -> bool:
    """Whether any policy entry names this tool.

    A namespaced entry is compared against the exposed name, which is how the
    operator wrote it and how the agent sees it. A bare entry is compared against
    the downstream tool name, which configuration only permits when a single
    server is configured and the name cannot be ambiguous.

    Comparison is exact. No prefix, substring or case-insensitive matching: a
    permission that matched more than it named would widen access by accident.
    """
    for entry in entries:
        if NAMESPACE_SEPARATOR in entry:
            if entry == exposed_name:
                return True
        elif entry == original_name:
            return True
    return False
