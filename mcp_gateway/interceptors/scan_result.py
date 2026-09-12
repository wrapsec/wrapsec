# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Tool results, inspected before they return to the agent.

The primary control. A tool result is content the agent asked for and will act
on, produced by a server the gateway does not control and shaped by whatever the
tool read -- a file, a web page, a database row. Indirect prompt injection lives
here: text that was never typed by the user arrives in the model's context
carrying the authority of "the tool said so".

THE PARTS ARE JOINED AND JUDGED TOGETHER. A payload split across two content
blocks is invisible to any single-block scan, and one verdict per result is also
one API call per result rather than one per block, which matters in the agent's
own latency path. Joining with newlines means an injection cannot be assembled
across a boundary that did not exist in the original.

A BLOCKED RESULT IS REFUSED WHOLE. Blocks arrive together from one call the
gateway has just judged malicious; forwarding the image while refusing the text
hands the agent half an attacker-controlled payload. Non-text content in a
blocked result goes with it.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_gateway.decision import Refusal
from mcp_gateway.mcp_compat import text_parts_of
from mcp_gateway.scanner import SOURCE_TOOL_RESULT, ScannerProtocol

logger = logging.getLogger(__name__)


class ToolResultScanner:
    """Judges what a tool returned before the agent sees it."""

    def __init__(self, scanner: ScannerProtocol, *, enabled: bool = True) -> None:
        self._scanner = scanner
        self._enabled = enabled

    async def inspect(
        self, *, server_name: str, result: Any, trace_id: str,
        turn_index: int | None = None,
    ) -> tuple[Any | None, Refusal | None]:
        """Return the result to deliver, or (None, refusal) to withhold it."""
        if not self._enabled:
            return result, None

        parts = text_parts_of(result)
        if not parts:
            # Nothing readable to judge. The result may still carry binary
            # content, which this build does not scan; it is forwarded as it
            # arrived rather than refused, and that limit is recorded rather than
            # presented as a clean verdict.
            return result, None

        verdict = await self._scanner.scan(
            "\n".join(parts), source=SOURCE_TOOL_RESULT, trace_id=trace_id,
            turn_index=turn_index,
        )

        if verdict.blocked:
            logger.warning(
                "withholding a tool result from server %s: %s (trace %s)",
                server_name, verdict.reason, verdict.trace_id,
            )
            return None, Refusal(
                reason   = verdict.reason,
                trace_id = verdict.trace_id,
                detail   = f"tool result from server {server_name!r}",
                failed   = verdict.failed,
            )

        if verdict.sanitized is not None:
            logger.info(
                "sanitized a tool result from server %s (trace %s)",
                server_name, verdict.trace_id,
            )
            return _sanitized_result(result, verdict.sanitized), None

        return result, None


def _sanitized_result(original: Any, sanitized: str) -> Any:
    """The result with its readable content replaced by the sanitized text.

    The parts were judged as one block, so one block is what comes back. Keeping
    the original parts and substituting into them is not possible without knowing
    which part each redaction came from, and guessing would put unredacted text
    back in front of the model.

    Non-text blocks are dropped along with the originals. They were not judged,
    and this result has already been found to need redaction -- returning
    unexamined bytes from it would be trusting the half that was not checked.
    """
    from mcp import types

    return types.CallToolResult(
        content   = [types.TextContent(type="text", text=sanitized)],
        is_error  = bool(getattr(original, "is_error", False)),
    )
