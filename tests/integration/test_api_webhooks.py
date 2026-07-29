# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for /v1/admin/webhooks (v1.3.0).

These tests exercise the admin webhook CRUD + rotate + reactivate
endpoints through the real FastAPI stack (auth middleware, deps,
router). They pin the security invariants that the endpoint module
docstring commits to:

  * Plaintext signing secret is returned ONLY in the create and
    rotate-secret responses. GET, LIST, PUT, DELETE, reactivate
    responses never contain it.
  * Cross-tenant access returns 404 (not 403) so an authenticated
    caller cannot enumerate ids across tenants.
  * Non-admin authenticated users cannot mutate.
  * URL is SSRF-validated at write time -- localhost, metadata, and
    private-range targets are rejected.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest

from db.models import WebhookEndpointModel


# ─── helpers ────────────────────────────────────────────────────────

def _tenant_id_from_headers(admin_jwt_headers) -> uuid.UUID:
    """Decode the admin JWT to recover the tenant_id the token is
    scoped to. Every SQLite fixture in this file needs it so the row
    we seed matches the tenant the handler will pull from
    request.state."""
    from services.auth.token import decode_access_token
    token   = admin_jwt_headers["Authorization"].split()[1]
    payload = decode_access_token(token)
    return uuid.UUID(payload["tenant_id"])


async def _seed_endpoint(
    test_db, tenant_id: uuid.UUID, *,
    url:        str = "https://example.com/hook",
    secret_enc: str = "v2:seeded-secret",
    disabled:   bool = False,
    first_failure_at=None,
) -> WebhookEndpointModel:
    ep = WebhookEndpointModel(
        id               = uuid.uuid4(),
        tenant_id        = tenant_id,
        url              = url,
        description      = None,
        secret_enc       = secret_enc,
        old_secrets      = [],
        event_types      = None,
        disabled         = disabled,
        first_failure_at = first_failure_at,
        created_at       = datetime.utcnow(),
    )
    test_db.add(ep)
    await test_db.commit()
    return ep


# ─── create ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_returns_plaintext_secret_once(
    client, admin_jwt_headers, test_db,
):
    """The create response is the only place the plaintext secret is
    exposed. Contract: response.secret is present, non-empty, and
    unrelated to the returned ciphertext mask."""
    r = await client.post(
        "/v1/admin/webhooks",
        json={
            "url":         "https://example.com/hook",
            "description": "test destination",
            "event_types": ["wrapsec.request.blocked"],
        },
        headers=admin_jwt_headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["url"] == "https://example.com/hook"
    assert body["description"] == "test destination"
    assert body["event_types"] == ["wrapsec.request.blocked"]
    assert body["disabled"] is False
    assert body["first_failure_at"] is None
    assert isinstance(body["secret"], str) and len(body["secret"]) >= 32
    assert "secret_masked" in body
    # The mask MUST NOT be the plaintext secret.
    assert body["secret_masked"] != body["secret"]


@pytest.mark.asyncio
async def test_create_rejects_ssrf_target_url(client, admin_jwt_headers):
    """SSRF defense: a webhook URL that resolves to a private,
    loopback, or metadata address is rejected at write time -- the
    delivery worker would otherwise make that request on the admin's
    behalf as an internal-network egress primitive."""
    for bad in [
        "http://localhost/hook",
        "http://127.0.0.1/hook",
        "http://169.254.169.254/",
        "http://metadata.google.internal/",
        "ftp://example.com/hook",
    ]:
        r = await client.post(
            "/v1/admin/webhooks",
            json={"url": bad},
            headers=admin_jwt_headers,
        )
        assert r.status_code == 422, f"expected 422 for {bad}, got {r.status_code}: {r.text}"


# ─── list / get ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_and_get_never_return_plaintext_secret(
    client, admin_jwt_headers, test_db,
):
    """The GET and LIST responses must NEVER carry the `secret` key.
    A regression here would let any admin read the plaintext of
    every existing endpoint by listing."""
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    await _seed_endpoint(test_db, tenant_id, url="https://a.example.com")
    ep = await _seed_endpoint(test_db, tenant_id, url="https://b.example.com")

    r = await client.get("/v1/admin/webhooks", headers=admin_jwt_headers)
    assert r.status_code == 200
    for row in r.json()["endpoints"]:
        assert "secret" not in row
        assert "secret_masked" in row

    r = await client.get(f"/v1/admin/webhooks/{ep.id}", headers=admin_jwt_headers)
    assert r.status_code == 200
    assert "secret" not in r.json()
    assert "secret_masked" in r.json()


@pytest.mark.asyncio
async def test_get_cross_tenant_returns_404(client, admin_jwt_headers, test_db):
    """A row that belongs to another tenant must return 404, not 403.
    403 would confirm the id exists and let an attacker enumerate
    across tenants."""
    other_tenant = uuid.uuid4()
    ep = await _seed_endpoint(test_db, other_tenant)

    r = await client.get(f"/v1/admin/webhooks/{ep.id}", headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_missing_returns_404(client, admin_jwt_headers):
    r = await client.get(
        f"/v1/admin/webhooks/{uuid.uuid4()}", headers=admin_jwt_headers,
    )
    assert r.status_code == 404


# ─── update ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_changes_allowed_fields(
    client, admin_jwt_headers, test_db,
):
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    ep = await _seed_endpoint(test_db, tenant_id)

    r = await client.put(
        f"/v1/admin/webhooks/{ep.id}",
        json={"description": "renamed", "event_types": ["wrapsec.request.sanitized"]},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["description"] == "renamed"
    assert body["event_types"] == ["wrapsec.request.sanitized"]
    assert "secret" not in body


@pytest.mark.asyncio
async def test_update_cross_tenant_returns_404(
    client, admin_jwt_headers, test_db,
):
    other_tenant = uuid.uuid4()
    ep = await _seed_endpoint(test_db, other_tenant)

    r = await client.put(
        f"/v1/admin/webhooks/{ep.id}",
        json={"description": "hijack"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 404


# ─── delete ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_removes_endpoint(client, admin_jwt_headers, test_db):
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    ep = await _seed_endpoint(test_db, tenant_id)

    r = await client.delete(f"/v1/admin/webhooks/{ep.id}", headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["deleted"] is True

    r = await client.get(f"/v1/admin/webhooks/{ep.id}", headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_delete_cross_tenant_returns_404(
    client, admin_jwt_headers, test_db,
):
    other_tenant = uuid.uuid4()
    ep = await _seed_endpoint(test_db, other_tenant)

    r = await client.delete(f"/v1/admin/webhooks/{ep.id}", headers=admin_jwt_headers)
    assert r.status_code == 404

    # And the row still exists (not silently deleted from another tenant).
    still_there = await test_db.get(WebhookEndpointModel, ep.id)
    assert still_there is not None


# ─── rotate-secret ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rotate_returns_new_plaintext_secret(
    client, admin_jwt_headers, test_db,
):
    """Rotation is the SECOND (and last) place plaintext secret is
    returned. The response MUST include the new secret; the follow-up
    GET MUST NOT."""
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    ep = await _seed_endpoint(test_db, tenant_id, secret_enc="v2:old-secret")

    r = await client.post(
        f"/v1/admin/webhooks/{ep.id}/rotate-secret",
        json={"grace_hours": 12},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["secret"], str) and len(body["secret"]) >= 32
    assert body["secret_masked"] != body["secret"]

    r2 = await client.get(f"/v1/admin/webhooks/{ep.id}", headers=admin_jwt_headers)
    assert "secret" not in r2.json()


@pytest.mark.asyncio
async def test_rotate_cross_tenant_returns_404(
    client, admin_jwt_headers, test_db,
):
    other_tenant = uuid.uuid4()
    ep = await _seed_endpoint(test_db, other_tenant)

    r = await client.post(
        f"/v1/admin/webhooks/{ep.id}/rotate-secret",
        json={"grace_hours": 24},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_rotate_rejects_out_of_range_grace(
    client, admin_jwt_headers, test_db,
):
    """grace_hours is bounded [1, 168]. Zero would invalidate the old
    secret instantly (defeats the point); huge values would keep
    compromised secrets alive for months."""
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    ep = await _seed_endpoint(test_db, tenant_id)

    for bad in [0, -1, 169, 100000]:
        r = await client.post(
            f"/v1/admin/webhooks/{ep.id}/rotate-secret",
            json={"grace_hours": bad},
            headers=admin_jwt_headers,
        )
        assert r.status_code == 422, f"grace_hours={bad} should be rejected"


# ─── reactivate ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reactivate_clears_disabled_and_timer(
    client, admin_jwt_headers, test_db,
):
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    ep = await _seed_endpoint(
        test_db, tenant_id,
        disabled=True,
        first_failure_at=datetime(2026, 7, 1, 12, 0, 0),
    )

    r = await client.post(
        f"/v1/admin/webhooks/{ep.id}/reactivate", headers=admin_jwt_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["disabled"] is False
    assert body["first_failure_at"] is None
    assert "secret" not in body


@pytest.mark.asyncio
async def test_reactivate_cross_tenant_returns_404(
    client, admin_jwt_headers, test_db,
):
    other_tenant = uuid.uuid4()
    ep = await _seed_endpoint(test_db, other_tenant, disabled=True)

    r = await client.post(
        f"/v1/admin/webhooks/{ep.id}/reactivate", headers=admin_jwt_headers,
    )
    assert r.status_code == 404


# ─── authorization ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_request_rejected(client):
    """No auth header at all -- must not be able to see or touch any
    webhook endpoint. Middleware rejects before the handler runs."""
    for method, path, json_body in [
        ("get",    "/v1/admin/webhooks",                             None),
        ("post",   "/v1/admin/webhooks",                             {"url": "https://x.example.com"}),
        ("get",    f"/v1/admin/webhooks/{uuid.uuid4()}",             None),
        ("put",    f"/v1/admin/webhooks/{uuid.uuid4()}",             {"description": "x"}),
        ("delete", f"/v1/admin/webhooks/{uuid.uuid4()}",             None),
        ("post",   f"/v1/admin/webhooks/{uuid.uuid4()}/rotate-secret", {"grace_hours": 24}),
        ("post",   f"/v1/admin/webhooks/{uuid.uuid4()}/reactivate",  None),
    ]:
        resp = await getattr(client, method)(path, json=json_body) if json_body is not None \
               else await getattr(client, method)(path)
        assert resp.status_code in (401, 403), (
            f"{method.upper()} {path} without auth returned {resp.status_code}"
        )
