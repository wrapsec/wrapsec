# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Entry point: `python -m mcp_server` runs the WrapSec MCP server over stdio."""

from mcp_server.server import main

if __name__ == "__main__":
    main()
