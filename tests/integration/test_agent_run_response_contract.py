# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The agent-run timeline's response model is applied by the runtime.

Same instrument as the scan family: `_format_item` is wrapped to emit a field no
model declares, and the caller must never see it. The model drops it; a
`JSONResponse` would serve it. That is the assertion, and it fails the moment the
success return goes back to a Response object.

Three success branches, because they produce genuinely different bodies:

  * a populated timeline;
  * an EMPTY timeline -- an unknown or out-of-scope run_id is a 200 with
    `count: 0`, not a 404, which is what stops run ids being probed across
    tenants;
  * a PROXY turn, where `output_decision`, `provider` and `model` carry values
    instead of the nulls a scan-only turn has.

Null preservation is checked directly, because it is the half `exclude_unset`
could get wrong: every field of a turn is always present, and the empty ones are
null. Nothing in this projection is ever absent.
"""

import uuid

import pytest

from services.time import utc_now

_LEAK = "undeclared_internal_field"

_NO_DIGITS = str.maketrans("0123456789", "ghijklmnop")


def _unique() -> str:
    """Unique, and not shaped like an account number -- a raw hex blob reads as
    PII to the guardrail, which changes the verdict under test."""
    return uuid.uuid4().hex.translate(_NO_DIGITS)


@pytest.fixture
async def live_key(test_db):
    """A live key seeded per test, so this file's requests do not share the
    admin key's 60/min rate-limit bucket with every other file in the run."""
    import hashlib

    from db.models import APIKeyModel, DepartmentModel
    from db.repositories.tenant import TenantRepository

    tenant = await TenantRepository(test_db).get_bootstrap_default()
    assert tenant is not None

    dept_id = uuid.uuid4()
    test_db.add(DepartmentModel(
        id=dept_id, tenant_id=tenant.id, slug=f"ar-{dept_id.hex[:8]}",
        name="Agent run dept", is_active=True,
    ))
    await test_db.flush()

    raw = "wsk_live_" + uuid.uuid4().hex
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:8],
        tenant_id=tenant.id, dept_id=dept_id, app_id=None, name="agent-run-contract",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
    ))
    await test_db.commit()
    return {"x-api-key": raw}, tenant.id, dept_id


@pytest.fixture
def leaky_format_item(monkeypatch):
    """Emit a field no model declares, from the helper that builds each turn.

    Patched on `agent_runs`, which imported the name -- patching the audit module
    would not reach this route's call site.
    """
    from api.v1.endpoints import agent_runs

    original = agent_runs._format_item

    def _leaky(*args, **kwargs):
        turn = original(*args, **kwargs)
        turn[_LEAK] = "must not reach the caller"
        return turn

    monkeypatch.setattr(agent_runs, "_format_item", _leaky)
    return _leaky


async def _record_turns(client, headers, run_id: str, count: int = 2):
    for turn in range(count):
        r = await client.post(
            "/v1/ai/request", headers=headers,
            json={"input": f"agent contract turn {turn} {_unique()}",
                  "run_id": run_id, "session_id": f"sess-{run_id}", "turn_index": turn},
        )
        assert r.status_code == 200, r.text


# ── runtime enforcement, per success branch ──────────────────────────────────

@pytest.mark.asyncio
async def test_a_populated_timeline_drops_an_undeclared_field(
    client, live_key, leaky_format_item,
):
    headers, _, _ = live_key
    run_id = f"run-{_unique()}"
    await _record_turns(client, headers, run_id)

    r = await client.get(f"/v1/agent-runs/{run_id}", headers=headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] >= 1, "no scans came back, so nothing was filtered"
    for scan in body["scans"]:
        assert _LEAK not in scan, (
            "an undeclared field reached the caller: the response model is not "
            "being applied, so the success path is returning a Response object"
        )
    assert set(body) == {"run_id", "count", "scans"}, (
        f"the envelope carries unexpected keys: {sorted(set(body))}"
    )


@pytest.mark.asyncio
async def test_an_empty_timeline_is_a_200_with_the_same_envelope(client, live_key):
    """An unknown run_id is not an error. The envelope must be identical, so a
    client parses one shape either way."""
    headers, _, _ = live_key

    r = await client.get(f"/v1/agent-runs/run-{_unique()}", headers=headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"run_id", "count", "scans"}
    assert body["count"] == 0 and body["scans"] == []


@pytest.mark.asyncio
async def test_a_proxy_turn_carries_the_proxy_fields(client, live_key, test_db):
    """The branch where `output_decision`, `provider` and `model` are populated
    rather than null. Seeded directly, because reaching it through the proxy
    needs a live provider."""
    from db.models import AuditLogModel, ProxyInteractionModel

    headers, tenant_id, dept_id = live_key
    run_id = f"run-{_unique()}"

    pid = uuid.uuid4()
    test_db.add(ProxyInteractionModel(
        id=pid, trace_id="px-" + uuid.uuid4().hex[:10],
        input_decision="ALLOW", input_primary_reason="clean", input_confidence=0.1,
        execution_status="completed", total_latency_ms=120,
        provider="openai", model="gpt-4o", output_decision="ALLOW",
    ))
    await test_db.flush()
    test_db.add(AuditLogModel(
        id=uuid.uuid4(), trace_id="tr-" + uuid.uuid4().hex[:12], decision="ALLOW",
        risk_score=0.1, threats=[], input_hash="h", detection_mode="fast",
        execution_mode="proxy", llm_invoked=True, latency_ms=10.0, source="api",
        input_source="user_prompt", tenant_id=str(tenant_id), dept_id=str(dept_id),
        proxy_interaction_id=pid, run_id=run_id, session_id=f"sess-{run_id}",
        turn_index=0, created_at=utc_now(),
    ))
    await test_db.commit()

    r = await client.get(f"/v1/agent-runs/{run_id}", headers=headers)

    assert r.status_code == 200, r.text
    scans = r.json()["scans"]
    assert len(scans) == 1, f"expected the seeded proxy scan, got {len(scans)}"
    turn = scans[0]
    assert turn["output_decision"] == "ALLOW"
    assert turn["provider"] == "openai"
    assert turn["model"] == "gpt-4o"
    assert turn["execution_mode"] == "proxy"


# ── null preservation ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_empty_fields_are_null_and_still_present(client, live_key):
    """`exclude_unset` must not drop a key the writer set to None. Every field of
    a turn is always present; the empty ones are null."""
    headers, _, _ = live_key
    run_id = f"run-{_unique()}"
    await _record_turns(client, headers, run_id, count=1)

    r = await client.get(f"/v1/agent-runs/{run_id}", headers=headers)
    assert r.status_code == 200, r.text
    turn = r.json()["scans"][0]

    # A scan-only turn from a key with no application: these are null, not absent.
    for field in ("output_decision", "provider", "model", "app_id", "app_name", "user_id"):
        assert field in turn, f"{field} was dropped instead of being null"
        assert turn[field] is None, f"{field} was expected null, got {turn[field]!r}"

    # And the populated ones are still there, so the assertion above is not
    # passing on an empty body.
    for field in ("trace_id", "decision", "risk_score", "run_id", "turn_index",
                  "input_source", "severity", "record_hash"):
        assert field in turn, f"{field} is missing from the turn"
    assert turn["run_id"] == run_id


@pytest.mark.asyncio
async def test_the_turn_carries_exactly_the_declared_fields(client, live_key):
    """Pins the projection. A field added to `_format_item` without being added
    to the model would be silently dropped by the filter -- this is what makes
    that visible instead."""
    from api.v1.schemas.response import AuditItem

    headers, _, _ = live_key
    run_id = f"run-{_unique()}"
    await _record_turns(client, headers, run_id, count=1)

    r = await client.get(f"/v1/agent-runs/{run_id}", headers=headers)
    assert r.status_code == 200, r.text

    assert set(r.json()["scans"][0]) == set(AuditItem.model_fields), (
        "the served scan and the declared model disagree about the field set"
    )


# ── the documented failure ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_an_out_of_range_limit_returns_the_catalog_envelope(client, live_key):
    """The 422 this route declares. It is the catalog envelope at runtime, which
    is why the generated HTTPValidationError schema was replaced."""
    headers, _, _ = live_key

    r = await client.get(f"/v1/agent-runs/run-{_unique()}?limit=0", headers=headers)

    assert r.status_code == 422, r.text
    body = r.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["invalid_params"][0]["field"] == "limit"


# ── the timeline refuses a turn the model cannot accept ──────────────────────

@pytest.mark.asyncio
async def test_a_timeline_will_not_serve_an_invalid_turn(client, live_key, monkeypatch):
    """This family had no rejection probe at all: the test above proves the model
    FILTERS an undeclared field, which a body could also survive by accident.

    The corruption goes inside a LIST item rather than at the envelope, because
    that is the shape this route actually returns and the one a top-level check
    would miss. `turns` is a list of models, so a wrong-typed `risk_score` in one
    turn is caught only if validation recurses into each element rather than
    checking that the value is a list.
    """
    from fastapi.exceptions import ResponseValidationError

    from api.v1.endpoints import agent_runs

    original = agent_runs._format_item

    called = []

    def _corrupt(*args, **kwargs):
        called.append(True)
        turn = original(*args, **kwargs)
        turn["risk_score"] = "very"
        return turn

    monkeypatch.setattr(agent_runs, "_format_item", _corrupt)

    headers, _, _ = live_key
    run_id = f"run-{_unique()}"
    await _record_turns(client, headers, run_id, count=1)

    try:
        r = await client.get(f"/v1/agent-runs/{run_id}", headers=headers)
    except ResponseValidationError as rejected:
        assert "risk_score" in str(rejected), (
            f"validation rejected the timeline, but not for risk_score: {rejected}"
        )
        return

    # A clean 200 is not evidence: it is what an unapplied corruption also
    # produces. The writer must have run, and the only non-raising outcome
    # allowed is the 500 a served deployment returns.
    assert called, (
        "`_format_item` was never called, so no turn was corrupted and this "
        "test proved nothing about validation"
    )
    assert r.status_code == 500, (
        f"a turn violating the declared type was served with {r.status_code}, "
        "so validation is not recursing into the elements of `turns`"
    )


# ── the published vocabularies, checked against a real body ──────────────────

@pytest.mark.asyncio
async def test_a_timeline_only_carries_published_vocabulary_values(client, live_key):
    """`turns` is a list of `AuditItem`, which is where this family's
    vocabularies live -- so the check has to recurse into list elements rather
    than stopping at the envelope."""
    from ._vocabularies import assert_published_vocabulary, vocabulary_count

    assert vocabulary_count("AgentRunResponse") > 0, (
        "AgentRunResponse publishes no vocabularies, so this check walks nothing"
    )

    headers, _, _ = live_key
    run_id = f"run-{_unique()}"
    await _record_turns(client, headers, run_id, count=1)

    r = await client.get(f"/v1/agent-runs/{run_id}", headers=headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scans"], "no scans came back, so nothing was checked"
    assert_published_vocabulary(body, "AgentRunResponse")
