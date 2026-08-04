# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec MCP server -- an opt-in interface adapter exposing the WrapSec scan as a
Model Context Protocol tool, so any MCP-compatible agent can call it natively.

Architecture: a thin edge adapter over the WrapSec Python SDK client (the SDK is
the stable interface to WrapSec), so no gateway internals are imported here. The
core adapter logic (`mcp_server.tool.run_scan`) is pure over an injected client
and is unit-tested without the `mcp` package; `mcp_server.server` wires it into an
MCP server (the SDK's high-level MCPServer API) that speaks the protocol.

The package is named `mcp_server` (not `mcp`) so it does not shadow the MCP
protocol SDK's own top-level `mcp` module.

Run:  python -m mcp_server    (after `pip install -r requirements-mcp.txt`)
"""
