# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Refusals that happen before inspection leave no row in the decision trail.

`audit_logs` is the tamper-evident record of decisions about content. A request
refused before anything was examined has no decision, no risk score and no input
hash, so a row there has to invent them -- and `decision` feeds block-rate and
threat analytics, so an invented value inflates the numbers the product is judged
on with requests nobody ever looked at.

That rule currently lives in a docstring, which nothing enforces. Adding an audit
write to a refusal path looks like an improvement while it is being written; the
harm only shows up later, in a report. These tests are what makes that change
fail.

The positive control is the load-bearing part. A test asserting "no rows
appeared" passes just as happily when the harness cannot write rows at all, so
each case is measured against a request that IS inspected and DOES leave exactly
one row.
"""

import hashlib
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from config.settings import get_settings
from db.models import AuditLogModel
from security.encryption import encrypt

settings = get_settings()


@pytest.fixture
def app():
    from api.main import app
    return app


async def _seed_tenant_key(test_db, *, key_type="live", with_provider=True):
    """A real tenant, key, and (optionally) a provider config."""
    from db.models import (
        APIKeyModel,
        DepartmentModel,
        ProxyProviderConfigModel,
        TenantModel,
    )

    tid = uuid.uuid4()
    did = uuid.uuid4()
    raw = "wsk_live_" + uuid.uuid4().hex if key_type == "live" else "wsk_trial_" + uuid.uuid4().hex

    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await test_db.commit()
    test_db.add(DepartmentModel(id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}",
                                name="D", is_active=True))
    await test_db.commit()
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:12],
        tenant_id=tid, dept_id=did, name="k",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type=key_type, is_admin=False, revoked=False,
    ))
    if with_provider:
        test_db.add(ProxyProviderConfigModel(
            id=uuid.uuid4(), tenant_id=str(tid), provider="openai",
            base_url="https://api.openai.com/v1",
            provider_api_key_enc=encrypt("sk-test-key-1234567890", settings.secret_key),
            default_model="gpt-4o", timeout_seconds=30,
        ))
    await test_db.commit()
    return raw, tid


async def _rows_for(test_db, tenant_id) -> int:
    return (await test_db.execute(
        select(func.count()).select_from(AuditLogModel)
        .where(AuditLogModel.tenant_id == str(tenant_id))
    )).scalar_one()


async def _post(app, api_key, body, headers=None, path="/v1/chat/completions"):
    transport = ASGITransport(app=app, client=("203.0.113.9", 43210))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(
            path, headers={"x-api-key": api_key, **(headers or {})}, json=body,
        )


# ── The control: an inspected request DOES leave exactly one row ──────────────

class TestTheTrailIsWritable:
    """
    Without this, every assertion below could be passing because nothing in this
    setup can write to `audit_logs` at all.
    """

    @pytest.mark.asyncio
    async def test_an_inspected_request_writes_one_row(self, app, test_db):
        raw, tid = await _seed_tenant_key(test_db)
        before = await _rows_for(test_db, tid)

        resp = await _post(app, raw, {"input": "hello"}, path="/v1/ai/request")

        assert resp.status_code == 200, resp.text
        assert await _rows_for(test_db, tid) == before + 1


# ── Refused before inspection: nothing in the decision trail ──────────────────

class TestInvalidRequestsAreNotPersisted:
    """A client bug is not a security decision."""

    @pytest.mark.asyncio
    async def test_a_malformed_model_string_writes_no_row(self, app, test_db):
        raw, tid = await _seed_tenant_key(test_db)
        before = await _rows_for(test_db, tid)

        resp = await _post(app, raw, {
            "model": "gpt-4o",   # missing the provider prefix
            "messages": [{"role": "user", "content": "hi"}],
        })

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_model_format"
        assert await _rows_for(test_db, tid) == before

    @pytest.mark.asyncio
    async def test_a_conversation_with_nothing_scannable_writes_no_row(self, app, test_db):
        raw, tid = await _seed_tenant_key(test_db)
        before = await _rows_for(test_db, tid)

        resp = await _post(app, raw, {
            "model": "openai/gpt-4o",
            "messages": [{"role": "system", "content": "you are terse"}],
        })

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_messages"
        assert await _rows_for(test_db, tid) == before

    @pytest.mark.asyncio
    async def test_a_conversation_over_the_maximum_writes_no_row(self, app, test_db):
        """
        Worth its own case: this refusal happens AFTER the messages were
        selected, so it is the one most likely to acquire an audit write by
        someone reasoning that the request got far enough to deserve a record.
        """
        raw, tid = await _seed_tenant_key(test_db)
        before = await _rows_for(test_db, tid)
        over   = get_settings().max_scan_all_messages + 1

        resp = await _post(app, raw, {
            "model": "openai/gpt-4o",
            "messages": [{"role": "user", "content": f"m{i}"} for i in range(over)],
        }, headers={"X-WrapSec-Scan-All-Messages": "true"})

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "too_many_messages"
        assert await _rows_for(test_db, tid) == before

    @pytest.mark.asyncio
    async def test_an_unsupported_role_writes_no_row(self, app, test_db):
        """Refused by the request schema, so the handler never runs at all."""
        raw, tid = await _seed_tenant_key(test_db)
        before = await _rows_for(test_db, tid)

        resp = await _post(app, raw, {
            "model": "openai/gpt-4o",
            "messages": [{"role": "tool", "content": "tool output"}],
        })

        assert resp.status_code == 422
        assert await _rows_for(test_db, tid) == before


class TestProviderConfigRefusalsAreNotPersisted:
    """Operator misconfiguration is not a security decision either."""

    @pytest.mark.asyncio
    async def test_no_provider_configured_writes_no_row(self, app, test_db):
        raw, tid = await _seed_tenant_key(test_db, with_provider=False)
        before = await _rows_for(test_db, tid)

        resp = await _post(app, raw, {
            "model": "openai/gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
        })

        assert resp.status_code in (400, 503)
        assert resp.json()["error"]["code"] == "proxy_not_configured"
        assert await _rows_for(test_db, tid) == before

    @pytest.mark.asyncio
    async def test_a_provider_mismatch_writes_no_row(self, app, test_db):
        """The tenant is configured for one provider and asked for another."""
        raw, tid = await _seed_tenant_key(test_db)   # configured: openai
        before = await _rows_for(test_db, tid)

        resp = await _post(app, raw, {
            "model": "ollama/llama3.2",
            "messages": [{"role": "user", "content": "hi"}],
        })

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "provider_mismatch"
        assert await _rows_for(test_db, tid) == before

    @pytest.mark.asyncio
    async def test_a_trial_key_writes_no_row(self, app, test_db):
        raw, tid = await _seed_tenant_key(test_db, key_type="trial")
        before = await _rows_for(test_db, tid)

        resp = await _post(app, raw, {
            "model": "openai/gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
        })

        assert resp.status_code == 403
        assert await _rows_for(test_db, tid) == before


# ── A source-network denial belongs to the credential log, not this one ───────

class TestIpDenialGoesToTheCredentialLog:
    """
    The refusal is recorded, but in `auth_events`. It is a statement about a
    credential, not about content: nothing was scanned, so there is no decision
    to chain.
    """

    @pytest.mark.asyncio
    async def test_a_denied_address_writes_no_decision_row(self, app, test_db):
        from db.models import APIKeyModel

        raw, tid = await _seed_tenant_key(test_db)
        await test_db.execute(
            APIKeyModel.__table__.update()
            .where(APIKeyModel.tenant_id == tid)
            .values(ip_allowlist=["10.0.0.0/8"])
        )
        await test_db.commit()
        before = await _rows_for(test_db, tid)

        resp = await _post(app, raw, {"input": "hi"}, path="/v1/ai/request")

        assert resp.status_code == 403
        assert await _rows_for(test_db, tid) == before

    @pytest.mark.asyncio
    async def test_the_same_denial_does_reach_the_credential_log(self, test_db, app):
        """The other half: not persisted THERE does not mean not persisted."""
        from db.models import APIKeyModel, AuthEventModel

        raw, tid = await _seed_tenant_key(test_db)
        await test_db.execute(
            APIKeyModel.__table__.update()
            .where(APIKeyModel.tenant_id == tid)
            .values(ip_allowlist=["10.0.0.0/8"])
        )
        await test_db.commit()

        await _post(app, raw, {"input": "hi"}, path="/v1/ai/request")

        rows = (await test_db.execute(
            select(AuthEventModel).where(AuthEventModel.tenant_id == tid)
        )).scalars().all()
        assert len(rows) == 1
        assert rows[0].action == "api_key_ip_denied"


class TestTheRefusalPathCannotReachTheTrail:
    """
    A structural guard, because the row counts above have a blind spot.

    They read the table after the response, so a write dispatched as a
    background task lands too late to be seen and the assertion passes. That is
    not a hypothetical shape -- "log it without slowing the response down" is
    exactly how someone would add it. Waiting for it would make every test here
    slow and flaky, so the source is checked instead: the shared refusal helper
    has no business touching the decision trail at all, whenever it runs.
    """

    def test_the_shared_refusal_helper_does_not_touch_the_decision_trail(self):
        import inspect

        from api.v1.endpoints import proxy

        source = inspect.getsource(proxy._reject)
        for forbidden in ("AuditRepository", "audit_logs", "AuditLogModel"):
            assert forbidden not in source, (
                f"_reject references {forbidden}: a refusal that was never inspected "
                "must not reach the decision trail, and a background write would not "
                "be caught by the row counts in this file"
            )

    def test_the_refusal_helper_is_still_the_single_path(self):
        """
        The guard above is only worth anything while every refusal goes through
        that helper. If refusals start being built inline, it stops covering
        them and this is the reminder to widen it.
        """
        import inspect

        from api.v1.endpoints import proxy

        handler = inspect.getsource(proxy.proxy_chat_completions)
        assert handler.count("_reject(") >= 7, (
            "pre-inspection refusals no longer funnel through _reject; the "
            "structural guard above needs widening to match"
        )
