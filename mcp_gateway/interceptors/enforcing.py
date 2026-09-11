# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The interceptor that actually enforces.

Binds the per-boundary inspectors to the seam the proxy consults. It holds no
detection logic itself: each hook delegates to the inspector for that boundary,
and the hooks that later phases fill are explicit about inspecting nothing yet
rather than silently allowing.
"""

from __future__ import annotations

from typing import Any

from mcp_gateway.decision import Refusal
from mcp_gateway.interceptors.scan_tools import ToolDefinitionScanner


class EnforcingInterceptor:
    """Applies the inspections this build implements."""

    def __init__(self, *, tool_definitions: ToolDefinitionScanner) -> None:
        self._tool_definitions = tool_definitions
        self._refusals: list[Refusal] = []

    async def on_tool_definition(self, *, server_name: str, definition: Any) -> Any | None:
        published, refusal = await self._tool_definitions.inspect(
            server_name = server_name,
            definition  = definition,
            trace_id    = _trace(),
        )
        if refusal is not None:
            self._refusals.append(refusal)
        return published

    async def on_tool_call(self, **kwargs: Any) -> Refusal | None:
        # Call validation is not implemented in this build. Returning None allows
        # the call, which is stated here rather than left to be inferred from an
        # empty method: the gateway's tool-call boundary is not yet enforced.
        return None

    async def on_tool_result(self, *, server_name: str, result: Any, trace_id: str) -> Any:
        # Result scanning is not implemented in this build; the result is passed
        # through unexamined.
        return result

    @property
    def refusals(self) -> tuple[Refusal, ...]:
        """Every refusal this connection produced, for the operator record."""
        return tuple(self._refusals)


def _trace() -> str:
    import uuid

    return f"mcp_{uuid.uuid4().hex[:16]}"
