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


async def _record_scan(client, headers, run_id: str, turn_index: int):
    """Write one scan record into a run, through the real scan endpoint."""
    r = await client.post(
        "/v1/ai/request",
        json={
            "input":      f"agent run probe {uuid.uuid4().hex[:8]}",
            "run_id":     run_id,
            "session_id": f"sess_{run_id}",
            "turn_index": turn_index,
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text


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
    scans = data["scans"]
    # ordered by turn_index ascending regardless of insert order
    assert [t["turn_index"] for t in scans] == [0, 1, 2]
    # provenance is surfaced, including the untrusted tool turn
    assert scans[0]["input_source"] == "user_prompt"
    assert scans[1]["input_source"] == "tool_output"
    assert scans[2]["input_source"] == "user_prompt"
    # every scan shares the run_id
    assert all(t["run_id"] == run for t in scans)


@pytest.mark.asyncio
async def test_agent_run_unknown_returns_empty(client, admin_headers):
    resp = await client.get("/v1/agent-runs/run_does_not_exist_xyz", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 0
    assert data["scans"] == []


# ── the envelope counts scans, not turns ─────────────────────────────────────
#
# One turn can produce several scans: a tool call is judged on its arguments and
# again on its result, and one tool listing judges every definition it
# publishes. The field was called `turns` while holding scans, and `count` was
# documented as a turn count, so a run of 16 scans across 2 turns read as 16
# turns. These pin the corrected meaning.

@pytest.mark.asyncio
async def test_the_envelope_carries_scans_and_no_turns_field(client, admin_headers):
    run_id = f"run_{uuid.uuid4().hex[:12]}"
    await _record_scan(client, admin_headers, run_id, turn_index=0)

    body = (await client.get(f"/v1/agent-runs/{run_id}", headers=admin_headers)).json()

    assert "scans" in body, f"the envelope has no 'scans': {sorted(body)}"
    assert "turns" not in body, (
        "the response still carries the old 'turns' field; it held scan records, "
        "not turns, which is the mismatch this rename corrected"
    )


@pytest.mark.asyncio
async def test_count_is_the_number_of_scan_records(client, admin_headers):
    run_id = f"run_{uuid.uuid4().hex[:12]}"
    for turn in (0, 1, 2):
        await _record_scan(client, admin_headers, run_id, turn_index=turn)

    body = (await client.get(f"/v1/agent-runs/{run_id}", headers=admin_headers)).json()

    assert body["count"] == len(body["scans"]), (
        f"count={body['count']} disagrees with {len(body['scans'])} scan records"
    )


@pytest.mark.asyncio
async def test_several_scans_can_share_one_turn_index(client, admin_headers):
    """The shape that made the old name wrong.

    Four scans across two turns: `count` must be 4, and the distinct turn_index
    values must be 2. A caller derives the turn count from the records; the
    envelope does not carry a second counter that could disagree with them.
    """
    run_id = f"run_{uuid.uuid4().hex[:12]}"
    for turn_index in (1, 1, 2, 2):
        await _record_scan(client, admin_headers, run_id, turn_index=turn_index)

    body  = (await client.get(f"/v1/agent-runs/{run_id}", headers=admin_headers)).json()
    scans = body["scans"]

    assert body["count"] == 4, f"expected 4 scan records, got {body['count']}"
    assert len({s["turn_index"] for s in scans}) == 2, (
        f"expected 2 distinct turns across 4 scans, got "
        f"{sorted({s['turn_index'] for s in scans})}"
    )
