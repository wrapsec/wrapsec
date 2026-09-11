# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Serving one agent over stdin and stdout.

The V1 transport, and the reason the runtime model is one client per process:
the SDK's stdio server claims the process's own file descriptors, and a second
concurrent one raises. Multiple agents therefore mean multiple gateway
processes, each with its own downstream connections and its own correlation
scope.

STDOUT IS THE PROTOCOL. Anything written to it that is not a protocol message
corrupts the stream, so every diagnostic goes to stderr. The SDK redirects fd 1
to stderr while serving for exactly this reason, but the gateway configures its
own logging to stderr rather than relying on that.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

logger = logging.getLogger(__name__)


def configure_logging(level: int = logging.INFO) -> None:
    """Send every log record to stderr.

    A handler on stdout would interleave log lines with protocol frames and take
    the connection down, which in a security component would look like a fault in
    whatever was being inspected at the time.
    """
    root = logging.getLogger()
    root.setLevel(level)
    for existing in list(root.handlers):
        root.removeHandler(existing)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    ))
    root.addHandler(handler)


async def serve(server: Any) -> None:
    """Run one MCP connection to completion over stdio.

    Returns when the agent closes the stream. The dual-era loop inside the SDK
    serves both the legacy handshake and the modern per-request envelope; which
    one applies is decided by the client's first request, not by configuration
    here, so a single gateway build serves both protocol revisions.
    """
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )
