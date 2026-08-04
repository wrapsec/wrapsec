# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for the agent-run timeline endpoint (v1.7.0).

GET /v1/agent-runs/{run_id} returns a run's scans ordered by turn_index, derived
from audit_logs and tenant-scoped. Rows are created through the real
/v1/ai/request path so run_id / turn_index / input_source persist exactly as in
production. Texts carry a nonce so the semantic cache never suppresses a write.
"""

import uuid

import pytest


@pytest.mark.asyncio
async def test_agent_run_timeline_ordered(client, admin_headers):
    run   = f"run_{uuid.uuid4().hex[:10]}"
    nonce = uuid.uuid4().hex[:8]

    # Send turns OUT of order to prove server-side ordering by turn_index.
    turns_in = [
        (2, "user_prompt", f"third turn follow up {nonce}"),
        (0, "user_prompt", f"first turn hello {nonce}"),
        (1, "tool_output", f"please summarise this document {nonce}"),
    ]
    for turn, src, text in turns_in:
        r = await client.post(
            "/v1/ai/request",
            json={
                "input":        text,
                "run_id":       run,
                "session_id":   f"sess_{nonce}",
                "turn_index":   turn,
                "input_source": src,
            },
            headers=admin_headers,
        )
        assert r.status_code == 200

    resp = await client.get(f"/v1/agent-runs/{run}", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["run_id"] == run
    assert data["count"]  == 3
    turns = data["turns"]
    # ordered by turn_index ascending regardless of insert order
    assert [t["turn_index"] for t in turns] == [0, 1, 2]
    # provenance is surfaced, including the untrusted tool turn
    assert turns[0]["input_source"] == "user_prompt"
    assert turns[1]["input_source"] == "tool_output"
    assert turns[2]["input_source"] == "user_prompt"
    # every turn shares the run_id
    assert all(t["run_id"] == run for t in turns)


@pytest.mark.asyncio
async def test_agent_run_unknown_returns_empty(client, admin_headers):
    resp = await client.get("/v1/agent-runs/run_does_not_exist_xyz", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 0
    assert data["turns"] == []
