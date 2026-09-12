# MCP gateway acceptance

Proves the whole chain, not a part of it:

    MCP client -> python -m mcp_gateway -> downstream MCP server
                        |
                        v
                  live WrapSec API -> Postgres
                        |
                        v
              GET /v1/agent-runs/{run_id}

Not in the unit or integration tiers because it needs a live API on a real port,
which neither tier provides. It takes minutes rather than seconds, so it is run
deliberately rather than on every change.

    tests/acceptance/mcp_gateway/with_stack.sh \
        .venv/bin/python tests/acceptance/mcp_gateway/run_agent_run_timeline.py

The script decides success by EXIT STATUS. Nothing reads its output to judge the
result, because a check whose failure mode is silence is not a check.

It asserts the timeline records what the call actually did: the same run and
session throughout, the argument decision and the result decision sharing one
turn index, distinct trace ids, ordering that follows the call, and the poisoned
result recorded as BLOCK rather than merely present.
