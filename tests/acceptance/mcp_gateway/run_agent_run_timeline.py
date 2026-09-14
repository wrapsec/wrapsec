"""Acceptance: the whole chain, then read the timeline back.

MCP client -> gateway process -> downstream server, with a real API and a real
database behind the gateway, then GET /v1/agent-runs/{run_id}.

Exit status is the verdict. Nothing here decides success by looking for text in
output.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

ROOT   = Path("/home/kebi/projects/wrapsec")
# Running a script puts its OWN directory on sys.path, not the working
# directory, so the repo is not importable without this.
sys.path.insert(0, str(ROOT))
PY_    = str(ROOT / ".venv" / "bin" / "python")
SP     = Path(os.environ.get("SP", "/tmp"))   # scratch for logs only
API    = os.environ["API_BASE"]          # e.g. http://127.0.0.1:18000
KEY    = os.environ["ADMIN_KEY"]

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    config = SP / "acceptance.yaml"
    config.write_text(
        "servers:\n"
        "  - name: notes\n"
        "    command:\n"
        f"      - {PY_}\n"
        f"      - {Path(__file__).parent / '_poisoned_server.py'}\n"
        "wrapsec:\n"
        f"  base_url: {API}\n"
        "  api_key_env: WRAPSEC_API_KEY\n"
        "  timeout_s: 30\n"
        "scan:\n"
        "  mode: fast\n"
        "  tool_definitions: false\n"     # keep the timeline to the call itself
        "  results: true\n"
        "  call_arguments: true\n",
        encoding="utf-8",
    )

    import anyio

    errlog_path = SP / "gateway.err"

    async def drive(errlog):
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        params = StdioServerParameters(
            command=PY_, args=["-m", "mcp_gateway"],
            env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(ROOT),
                 "WRAPSEC_MCP_CONFIG": str(config), "WRAPSEC_API_KEY": KEY,
                 "WRAPSEC_ENV": "production"},
        )
        async with (
            stdio_client(params, errlog=errlog) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
            name  = tools.tools[0].name
            out   = await session.call_tool(name, {"path": "/tmp/notes.txt"})
            body  = " ".join(b.text for b in (out.content or [])
                             if getattr(b, "text", None))
            return out.is_error, body

    with errlog_path.open("w") as errlog:
        is_error, body = anyio.run(drive, errlog)

    # -- the call itself -----------------------------------------------------
    check(is_error is True, "the poisoned result was delivered to the agent")
    check("Ignore all previous instructions" not in body,
          "the blocked payload was echoed back to the agent")
    check("Do not retry" in body, "the refusal did not tell the agent to stop")

    # -- the identifiers the gateway minted -----------------------------------
    stderr = errlog_path.read_text()
    found  = re.search(r"session=(\S+) run=(\S+)", stderr)
    check(found is not None, "the gateway did not report its correlation scope")
    if not found:
        return _report()
    session_id, run_id = found.group(1), found.group(2)

    # -- read the timeline back ----------------------------------------------
    import httpx

    timeline = None
    for _ in range(20):                       # audit writes settle asynchronously
        resp = httpx.get(f"{API}/v1/agent-runs/{run_id}",
                         headers={"x-api-key": KEY}, timeout=20)
        if resp.status_code == 200 and resp.json().get("scans"):
            timeline = resp.json()
            break
        time.sleep(1)

    check(timeline is not None, f"no timeline returned for run {run_id}")
    if timeline is None:
        return _report()

    items = timeline["scans"]
    print(json.dumps({"run_id": run_id, "session_id": session_id,
                      "scans": len(items)}, indent=2))
    for item in items:
        print("   ", {k: item.get(k) for k in
                      ("turn_index", "trace_id", "decision", "primary_reason",
                       "input_source", "session_id", "run_id")})

    # -- the assertions the acceptance criterion asks for ---------------------
    check(all(i.get("run_id") == run_id for i in items),
          "an item carried a different run_id")
    check(all(i.get("session_id") == session_id for i in items),
          "an item carried a different session_id")

    # Arguments are declared as agent_tool_call, not user_prompt: they are text
    # a model composed, and the source is what puts them in the untrusted tier.
    # Asserted against the value the gateway module declares rather than a
    # literal, so the two cannot drift apart silently.
    from mcp_gateway.scanner import SOURCE_TOOL_ARGUMENT, SOURCE_TOOL_RESULT

    args   = [i for i in items if i.get("input_source") == SOURCE_TOOL_ARGUMENT]
    result = [i for i in items if i.get("input_source") == SOURCE_TOOL_RESULT]
    check(SOURCE_TOOL_ARGUMENT == "agent_tool_call",
          f"arguments are declared as {SOURCE_TOOL_ARGUMENT!r}")
    check(len(args) == 1, f"expected one argument decision, got {len(args)}")
    check(len(result) == 1, f"expected one result decision, got {len(result)}")
    check(not [i for i in items if i.get("input_source") == "user_prompt"],
          "a decision was recorded as user_prompt; nothing the gateway scans is "
          "content a person typed")
    if not (args and result):
        return _report()

    check(args[0]["turn_index"] == result[0]["turn_index"],
          f"the result took turn {result[0]['turn_index']} instead of inheriting "
          f"{args[0]['turn_index']}")
    check(args[0]["trace_id"] != result[0]["trace_id"],
          "the two decisions share a trace id")
    check(args[0]["decision"] == "ALLOW",
          f"the benign arguments were {args[0]['decision']}, not ALLOW")
    check(result[0]["decision"] == "BLOCK",
          f"the poisoned result was {result[0]['decision']}, not BLOCK")

    order = [i["trace_id"] for i in items]
    check(order.index(args[0]["trace_id"]) < order.index(result[0]["trace_id"]),
          "the timeline orders the result before the call that produced it")

    return _report()


def _report() -> int:
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nacceptance: the timeline matches the call")
    return 0


if __name__ == "__main__":
    sys.exit(main())
