# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A real downstream MCP server, for driving the gateway end to end.

Run as a subprocess by the integration test. Not a test module itself: the
leading underscore keeps it out of collection.

Its identity is taken from argv so one script can stand in for several distinct
downstream servers, which is what makes routing identity observable -- each
answers with its own name, so a result proves which server actually ran.
"""

from __future__ import annotations

import sys

from mcp.server import MCPServer


def build(identity: str) -> MCPServer:
    server = MCPServer(f"fake-{identity}")

    @server.tool()
    def whoami() -> str:
        """Report which downstream server handled the call."""
        return f"handled by {identity}"

    @server.tool()
    def echo(text: str) -> str:
        """Return the text unchanged."""
        return f"{identity}:{text}"

    return server


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "unnamed").run()
