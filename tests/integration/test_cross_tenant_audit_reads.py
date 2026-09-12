# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Every audit READ endpoint must scope to the caller's tenant, not just /logs.

`get_audit_scope` is applied at seven call sites. Neutering it at one place at a
time showed only `/logs` was covered: `/stats`, `/attribution`, `/analytics`,
`/by-source`, `/export` and `GET /agent-runs/{run_id}` could each be left
unscoped, and all six together left the full integration suite green. The helper
returns a dict the endpoint has to apply, so testing the helper says nothing
about whether an endpoint used what it returned.

These are read paths over the whole audit trail -- `/export` is a bulk dump and
`/agent-runs/{run_id}` returns a complete agent timeline -- so an endpoint that
forgets to apply the scope hands one tenant another's traffic.

Assertions are differential or marker-based rather than absolute counts: these
tests use `auth_client`, which does not truncate `audit_logs`, so rows from
other tests are present and a fixed total would be meaningless. Either a value
must not move when another tenant gains rows, or a marker unique to the other
tenant must not appear.
"""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from config.settings import get_settings

settings = get_settings()


async def _add_rows_for(
    tenant, *, marker: str, n: int = 4, input_source: str = "user_prompt",
) -> str:
    """
    Give one tenant extra traffic carrying a marker unique to it.

    Returns the marker. `source` is used because /by-source and /attribution
    both project it, so a single marker is visible from several endpoints.
    """
    from db.models import AuditLogModel

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with sf() as db:
            for i in range(n):
                db.add(AuditLogModel(
                    id=uuid.uuid4(),
                    trace_id=f"{marker}-{i}",
                    decision="BLOCK" if i % 2 else "ALLOW",
                    risk_score=0.9 if i % 2 else 0.1,
                    threats=[],
                    input_hash="hash-" + uuid.uuid4().hex,
                    detection_mode="standard", execution_mode="scan",
                    llm_invoked=False, latency_ms=11.0,
                    tenant_id=str(tenant["tenant"].id),
                    dept_id=str(tenant["dept"].id),
                    app_id=str(tenant["app"].id),
                    key_id=tenant["api_key_id"],
                    source=marker,
                    input_source=input_source,
                ))
            await db.commit()
    finally:
        await engine.dispose()
    return marker


def _auth(tenant) -> dict:
    return {"Authorization": f"Bearer {tenant['admin_token']}"}


# ── Endpoints that project an identifier: the marker must not appear ──────────

@pytest.mark.parametrize("path", [
    "/v1/audit/export?format=json",
    "/v1/audit/attribution",
])
@pytest.mark.asyncio
async def test_a_tenant_never_sees_another_tenants_traffic(
    auth_client, two_tenant_setup, path,
):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    marker = await _add_rows_for(b, marker="XTENANT-" + uuid.uuid4().hex[:12])

    resp = await auth_client.get(path, headers=_auth(a))
    assert resp.status_code == 200, f"{path}: {resp.status_code} {resp.text[:200]}"
    assert marker not in resp.text, (
        f"{path} returned tenant B's traffic to tenant A"
    )


@pytest.mark.asyncio
async def test_by_source_does_not_report_another_tenants_provenance(
    auth_client, two_tenant_setup,
):
    """
    /by-source groups by `input_source`, not by `source`, so the marker the
    other endpoints are checked with is invisible here and an assertion on it
    would pass whatever the endpoint returned. The provenance VALUE is the
    identifier that reaches this response, so tenant B gets one that tenant A
    never uses.
    """
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]

    before = await auth_client.get("/v1/audit/by-source", headers=_auth(a))
    assert before.status_code == 200, before.text
    assert all(s["input_source"] != "tool_output" for s in before.json()["sources"]), (
        "tenant A already has tool_output traffic, so its later absence would "
        "prove nothing"
    )

    await _add_rows_for(
        b, marker="XTENANT-" + uuid.uuid4().hex[:12], input_source="tool_output",
    )

    after = await auth_client.get("/v1/audit/by-source", headers=_auth(a))
    assert after.status_code == 200, after.text
    assert all(s["input_source"] != "tool_output" for s in after.json()["sources"]), (
        "tenant A's by-source report counted tenant B's tool_output traffic"
    )


# ── Aggregates carry no identifier: assert the numbers do not move ────────────

@pytest.mark.parametrize("path,field", [
    ("/v1/audit/stats",     "total_requests"),
    ("/v1/audit/analytics", "total"),
])
@pytest.mark.asyncio
async def test_another_tenants_volume_does_not_change_the_totals(
    auth_client, two_tenant_setup, path, field,
):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]

    before = await auth_client.get(path, headers=_auth(a))
    assert before.status_code == 200, before.text
    baseline = before.json()[field]

    await _add_rows_for(b, marker="XTENANT-" + uuid.uuid4().hex[:12], n=5)

    after = await auth_client.get(path, headers=_auth(a))
    assert after.status_code == 200, after.text
    assert after.json()[field] == baseline, (
        f"{path}: tenant A's {field} moved from {baseline} to "
        f"{after.json()[field]} when tenant B gained traffic"
    )


# ── GET /agent-runs/{run_id} ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_an_agent_run_is_not_readable_across_tenants(
    auth_client, two_tenant_setup,
):
    """
    A run id is caller-supplied and opaque, so it is guessable in a way a
    database id is not. The timeline behind it is the full text-level history of
    one agent execution.
    """
    from db.models import AuditLogModel

    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    run_id = "run-" + uuid.uuid4().hex
    marker = "XRUN-" + uuid.uuid4().hex[:12]

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with sf() as db:
            db.add(AuditLogModel(
                id=uuid.uuid4(), trace_id=marker,
                decision="ALLOW", risk_score=0.1, threats=[],
                input_hash="hash-" + uuid.uuid4().hex,
                detection_mode="standard", execution_mode="scan",
                llm_invoked=False, latency_ms=12.0,
                tenant_id=str(b["tenant"].id), dept_id=str(b["dept"].id),
                app_id=str(b["app"].id), key_id=b["api_key_id"],
                source=marker, input_source="user_prompt",
                run_id=run_id, session_id=run_id, turn_index=0,
            ))
            await db.commit()
    finally:
        await engine.dispose()

    resp = await auth_client.get(f"/v1/agent-runs/{run_id}", headers=_auth(a))

    assert resp.status_code in (200, 404), resp.text
    assert marker not in resp.text, (
        "tenant A read tenant B's agent-run timeline"
    )
    if resp.status_code == 200:
        assert not resp.json().get("scans"), (
            "the run resolved to tenant B's turns for a caller in tenant A"
        )
