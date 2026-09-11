# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A degraded policy resolution must reach the caller as a refusal, over HTTP.

The unit tests prove `resolve_policy` raises. That is not the same claim as
"the API refuses": an endpoint could catch the exception, or a handler could
convert it into something that looks like a verdict. These run the real routes
and assert what a caller actually receives.

The property that matters is negative and is asserted as such: the response must
NOT be a normal scan verdict. A 200 carrying `decision: ALLOW` would mean the
gateway judged a request without knowing the policy it was judging against,
which is the entire defect.
"""

from __future__ import annotations

import json

import pytest

_SCAN  = "/v1/ai/request"
_BATCH = "/v1/ai/scan-batch"


class _Boom(Exception):
    """Distinct from anything the resolver raises itself."""


@pytest.fixture
def tenant_read_fails(monkeypatch):
    """Break the stored-settings read, which is the tenant layer."""
    import db.repositories.settings as settings_repos

    class _Repo:
        def __init__(self, *a, **kw):
            pass

        async def get(self, *a, **kw):
            raise _Boom("simulated tenant settings failure")

    monkeypatch.setattr(settings_repos, "PlatformSettingsRepository", _Repo)
    monkeypatch.setattr(settings_repos, "TenantSettingsRepository",   _Repo)


@pytest.fixture
def dept_read_fails(monkeypatch):
    import services.policy_resolver as resolver

    class _Repo:
        def __init__(self, *a, **kw):
            pass

        async def get_by_id(self, *a, **kw):
            raise _Boom("simulated department failure")

    monkeypatch.setattr(resolver, "DepartmentRepository", _Repo)


@pytest.fixture
def app_read_fails(monkeypatch):
    import services.policy_resolver as resolver

    class _Repo:
        def __init__(self, *a, **kw):
            pass

        async def get_by_id(self, *a, **kw):
            raise _Boom("simulated application failure")

    monkeypatch.setattr(resolver, "ApplicationRepository", _Repo)


def _assert_refused(resp):
    """Refused, and refused as the fail-closed error -- not as a verdict."""
    assert resp.status_code == 500, (
        f"expected the fail-closed refusal, got {resp.status_code}: {resp.text[:300]}"
    )
    body = resp.json()
    assert set(body) == {"error"}, f"not the catalog envelope: {sorted(body)}"
    assert body["error"]["code"] == "DETECTION_ERROR", (
        f"refused with {body['error']['code']!r}; the refusal must land in the "
        "existing fail-closed vocabulary, not a parallel one"
    )
    # the negative half: nothing resembling a scan verdict came back
    assert "decision" not in body, "a verdict was served for an unresolved policy"


@pytest.mark.asyncio
async def test_the_scan_route_refuses_when_the_tenant_layer_fails(
    client, admin_headers, tenant_read_fails,
):
    _assert_refused(await client.post(_SCAN, json={"input": "hello"}, headers=admin_headers))


@pytest.mark.asyncio
async def test_the_batch_route_refuses_when_the_tenant_layer_fails(
    client, admin_headers, tenant_read_fails,
):
    _assert_refused(await client.post(
        _BATCH, json={"items": [{"input": "hello"}]}, headers=admin_headers,
    ))


async def _dept_scoped_key(test_db):
    """A live key bound to a department, so the resolver actually enters the
    department branch. The admin key carries no dept_id, so `if dept_id:` never
    fires for it and a department failure cannot be reached through it -- which
    is why these two cases need their own credential rather than reusing the
    admin one."""
    import hashlib
    import uuid as _uuid

    from db.models import APIKeyModel, DepartmentModel, TenantModel

    tid = _uuid.uuid4()
    did = _uuid.uuid4()
    raw = "wsk_live_" + _uuid.uuid4().hex

    test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
    await test_db.commit()
    test_db.add(DepartmentModel(id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}",
                                name="D", is_active=True))
    await test_db.commit()
    test_db.add(APIKeyModel(
        id=_uuid.uuid4(), key_id="key_" + _uuid.uuid4().hex[:12],
        tenant_id=tid, dept_id=did, name="k",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
    ))
    await test_db.commit()
    return {"x-api-key": raw}


@pytest.mark.asyncio
async def test_the_scan_route_refuses_when_the_department_layer_fails(
    client, test_db, dept_read_fails,
):
    """Covered separately from the tenant layer because it used to be handled by
    a DIFFERENT branch -- an inner try that logged a warning and continued, so
    the request was served as though resolution had succeeded."""
    headers = await _dept_scoped_key(test_db)
    resp = await client.post(_SCAN, json={"input": "hello"}, headers=headers)
    if resp.status_code == 200:
        pytest.fail(
            "the scan was served while the department override could not be "
            "loaded; that override may have tightened this tenant's policy"
        )
    _assert_refused(resp)


@pytest.mark.asyncio
async def test_the_scan_route_refuses_when_the_application_layer_fails(
    client, test_db, app_read_fails, dept_read_fails,
):
    """`app_read_fails` alone is not enough: the admin key carries no app_id, so
    a department-scoped key is used and the department branch is broken too --
    either layer failing must refuse."""
    headers = await _dept_scoped_key(test_db)
    resp = await client.post(_SCAN, json={"input": "hello"}, headers=headers)
    if resp.status_code == 200:
        pytest.fail("the scan was served while the application override could not be loaded")
    _assert_refused(resp)


@pytest.mark.asyncio
async def test_a_healthy_resolution_still_serves_a_verdict(client, admin_headers):
    """The control. Every assertion above is satisfied by an API that refuses
    everything; this is what makes them mean something."""
    resp = await client.post(_SCAN, json={"input": "a perfectly ordinary prompt"},
                             headers=admin_headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["decision"] in ("ALLOW", "SANITIZE", "BLOCK")


@pytest.mark.asyncio
async def test_the_runtime_schema_and_the_committed_artifact_agree_on_the_new_500(client):
    """The declaration must exist in BOTH. The committed artifact is what
    consumers generate from; the runtime document is what the deployment serves,
    and a guard that only reads the file would not notice them diverging."""
    from pathlib import Path

    committed = json.loads(
        (Path(__file__).resolve().parents[2] / "docs" / "openapi.json").read_text()
    )
    served = (await client.get("/openapi.json")).json()

    for path in ("/v1/ai/request", "/v1/ai/scan-batch"):
        assert "500" in committed["paths"][path]["post"]["responses"], (
            f"{path} does not declare the 500 it can now answer"
        )
        assert "500" in served["paths"][path]["post"]["responses"], (
            f"the RUNTIME schema for {path} is missing the 500 the committed "
            "artifact declares"
        )
        ref = (served["paths"][path]["post"]["responses"]["500"]
               .get("content", {}).get("application/json", {})
               .get("schema", {}).get("$ref", ""))
        assert ref.endswith("ErrorEnvelope"), (
            f"{path} advertises {ref!r} for its 500; the runtime returns the "
            "catalog envelope"
        )


@pytest.mark.asyncio
async def test_the_chat_route_refuses_when_the_tenant_layer_fails(
    client, test_db, tenant_read_fails,
):
    """The proxy route refuses in the catalog envelope, not the OpenAI shape.

    Policy is resolved at step 2, before the provider config is loaded and long
    before anything OpenAI-compatible is produced, so the refusal is raised as a
    WrapSecError and answered by the global handler. That handler shapes every
    error the same way; it does not know this route speaks another protocol.

    The scan and batch routes were covered here and this one was not, which is
    how it came to declare its 500 as OpenAI-shaped only. A caller parsing
    `error.type` on this status would find no such field.
    """
    headers = await _dept_scoped_key(test_db)

    resp = await client.post(
        "/v1/chat/completions",
        json    = {"model": "openai/gpt-4o",
                   "messages": [{"role": "user", "content": "hello"}]},
        headers = headers,
    )

    _assert_refused(resp)
    # The negative half: NOT the OpenAI error shape this route uses elsewhere,
    # which is why the declaration has to carry both.
    assert "type" not in resp.json()["error"], (
        "the refusal came back in the OpenAI error shape; this test and the 500 "
        "declaration disagree about which producer answered"
    )
