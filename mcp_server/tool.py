# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Core scan-tool adapter for the WrapSec MCP server.

Pure over an injected WrapSec SDK client, so it is unit-tested without the `mcp`
package or a live server. `mcp_server.server` calls this from the FastMCP tool
handler.
"""

from __future__ import annotations

from typing import Any

DEFAULT_INPUT_SOURCE = "user_prompt"


def run_scan(client: Any, text: str, input_source: str = DEFAULT_INPUT_SOURCE) -> dict[str, Any]:
    """Scan `text` via the WrapSec SDK client and return the structured Security
    Assessment -- the MCP tool's result.

    Prefers the server-provided `assessment` object (decision, risk, reasons,
    per-layer contributions). Falls back to a minimal verdict assembled from the
    scan result for servers that predate the assessment field.
    """
    result = client.scan(text, input_source=input_source)

    assessment = getattr(result, "assessment", None)
    if assessment:
        return assessment

    return {
        "decision":       result.decision,
        "risk_score":     getattr(result, "risk_score", None),
        "primary_reason": result.primary_reason,
        "confidence":     getattr(result, "confidence", None),
        "threats":        list(getattr(result, "threats", []) or []),
        "layers":         [],
    }
