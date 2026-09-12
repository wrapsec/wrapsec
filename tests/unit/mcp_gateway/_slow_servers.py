# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A downstream server that accepts a tool call and never answers it.

Run as a subprocess by the timeout tests. Raw JSON-RPC rather than the SDK
helpers: a server that hangs is not being cooperative, and the question is what
the CLIENT does when no answer arrives.

Three tools, so one connection can prove the whole property:

  hang   accepted and never answered
  ping   answered immediately, proving the connection still works afterwards
  calls  answers with how many `hang` calls arrived, proving the gateway did
         not quietly retry the one that timed out
"""

from __future__ import annotations

import json
import sys

_hang_calls = 0


def send(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _tool(name: str, description: str) -> dict:
    return {"name": name, "description": description, "inputSchema": {"type": "object"}}


def main() -> None:
    global _hang_calls

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue

        method, mid = msg.get("method"), msg.get("id")

        if method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "slow", "version": "1"}}})

        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                _tool("hang",  "never answers"),
                _tool("ping",  "answers at once"),
                _tool("calls", "how many hang calls arrived"),
            ]}})

        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name")
            if name == "hang":
                _hang_calls += 1
                # Deliberately no response. The client's bound must end this.
                continue
            if name == "calls":
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": str(_hang_calls)}]}})
            else:
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": "pong"}]}})

        elif method == "notifications/cancelled":
            # The client's courtesy cancel for the abandoned call. Acknowledged
            # by ignoring it: it carries no id and expects no response.
            continue

        elif mid is not None:
            send({"jsonrpc": "2.0", "id": mid, "result": {}})


if __name__ == "__main__":
    main()
