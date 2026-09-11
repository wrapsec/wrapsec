# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""WrapSec MCP Gateway: a security sidecar for MCP-mediated agent tool use.

Runs as a standalone process between an MCP client and the downstream MCP
server(s) it uses. V1 supports stdio, and follows the standard MCP subprocess
model: one client launches one gateway process.
"""
