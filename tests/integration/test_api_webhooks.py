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

from db.models import TenantModel, WebhookEndpointModel, WebhookDeliveryAttemptModel


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
    # Real PG enforces webhook_endpoints.tenant_id -> tenants.id (SQLite did
    # not), so ensure the tenant row exists before seeding an endpoint under it.
    if await test_db.get(TenantModel, tenant_id) is None:
        test_db.add(TenantModel(
            id            = tenant_id,
            slug          = f"seed-{tenant_id.hex[:8]}",
            name          = "Seed Tenant",
            global_policy = {},
            is_active     = True,
        ))
        await test_db.flush()
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


@pytest.mark.asyncio
async def test_create_rejects_http_destination(client, admin_jwt_headers):
    """Webhook egress requires https by default (secure-by-default); a public
    http destination is rejected at create. The https check runs before DNS."""
    r = await client.post(
        "/v1/admin/webhooks",
        json={"url": "http://example.com/hook"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 400, r.text


# --- connector endpoints ---

@pytest.mark.asyncio
async def test_create_connector_endpoint_does_not_echo_secret(client, admin_jwt_headers):
    """A connector endpoint takes a customer-supplied ingest token; it is
    never echoed back (the customer already holds it), only masked. The
    projection surfaces connector_type, config, and the health status."""
    r = await client.post(
        "/v1/admin/webhooks",
        json={
            "url":            "https://hec.example.com:8088",
            "connector_type": "splunk_hec",
            "secret":         "hec-token-value",
            "config":         {"index": "security", "sourcetype": "wrapsec:security"},
        },
        headers=admin_jwt_headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["connector_type"] == "splunk_hec"
    assert body["config"] == {"index": "security", "sourcetype": "wrapsec:security"}
    assert body["status"] == "active"
    assert "secret" not in body                 # customer token never echoed
    assert body["secret_masked"]


@pytest.mark.asyncio
async def test_create_connector_requires_secret(client, admin_jwt_headers):
    r = await client.post(
        "/v1/admin/webhooks",
        json={"url": "https://hec.example.com:8088", "connector_type": "splunk_hec"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_create_connector_unknown_type_rejected(client, admin_jwt_headers):
    r = await client.post(
        "/v1/admin/webhooks",
        json={"url": "https://x.example.com", "connector_type": "bogus", "secret": "s"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_create_elastic_missing_required_config_rejected(client, admin_jwt_headers):
    r = await client.post(
        "/v1/admin/webhooks",
        json={"url": "https://es.example.com:9243", "connector_type": "elastic_ecs",
              "secret": "apikey"},   # config lacks required "index"
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_create_generic_rejects_supplied_secret(client, admin_jwt_headers):
    r = await client.post(
        "/v1/admin/webhooks",
        json={"url": "https://example.com/hook", "secret": "should-not-be-allowed"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_rotate_blocked_for_connector_endpoint(client, admin_jwt_headers):
    created = await client.post(
        "/v1/admin/webhooks",
        json={"url": "https://hec.example.com:8088", "connector_type": "splunk_hec",
              "secret": "hec-token", "config": {"index": "i"}},
        headers=admin_jwt_headers,
    )
    ep_id = created.json()["id"]
    r = await client.post(
        f"/v1/admin/webhooks/{ep_id}/rotate-secret",
        json={"grace_hours": 24},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_generic_projection_has_status_and_null_connector(client, admin_jwt_headers):
    created = await client.post(
        "/v1/admin/webhooks",
        json={"url": "https://example.com/hook"},
        headers=admin_jwt_headers,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["connector_type"] is None
    assert body["config"] is None
    assert body["status"] == "active"


@pytest.mark.asyncio
async def test_connector_types_schema_endpoint(client, admin_jwt_headers):
    """The dynamic-form schema endpoint returns generic + every connector, and
    the literal /connector-types path is not shadowed by GET /{endpoint_id}."""
    r = await client.get("/v1/admin/webhooks/connector-types", headers=admin_jwt_headers)
    assert r.status_code == 200, r.text
    entries = r.json()["connector_types"]
    types = {c["type"] for c in entries}
    assert None in types
    assert {"splunk_hec", "datadog_logs", "sentinel_logs_ingestion", "elastic_ecs"} <= types
    sentinel = next(c for c in entries if c["type"] == "sentinel_logs_ingestion")
    required = {f["key"] for f in sentinel["config_fields"] if f["required"]}
    assert "dcr_immutable_id" in required and "client_id" in required
    assert sentinel["secret"]["required"] is True


# --- test-send ---

@pytest.mark.asyncio
async def test_test_send_returns_receiver_outcome_and_leaks_no_secret(
    client, admin_jwt_headers, monkeypatch,
):
    """Test-send returns only the receiver-facing outcome (status/body/timing);
    the endpoint secret and outbound auth headers are never in the response.
    The synthetic event is clearly marked and carries no real data."""
    from services.webhooks import delivery_handler as dh

    captured = {}

    async def _fake_send_once(self, endpoint, event_type, body, msg_id):
        captured.update(event_type=event_type, body=body, msg_id=msg_id)
        return dh.SendResult(ok=True, status_code=200, response_snippet="ok",
                             duration_ms=12, error=None)

    monkeypatch.setattr(dh.WebhookDeliveryHandler, "send_once", _fake_send_once)

    created = await client.post(
        "/v1/admin/webhooks",
        json={"url": "https://example.com/hook"}, headers=admin_jwt_headers,
    )
    ep_id = created.json()["id"]

    r = await client.post(f"/v1/admin/webhooks/{ep_id}/test", headers=admin_jwt_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {"ok": True, "status_code": 200, "response_snippet": "ok",
                    "duration_ms": 12, "error": None}
    # No secret material or request internals leak into the response.
    for leaked in ("secret", "secret_masked", "headers", "token", "authorization"):
        assert leaked not in body
    # The event that was sent is a marked, synthetic test event.
    assert captured["event_type"] == "wrapsec.request.blocked"
    assert captured["body"]["test"] is True
    assert captured["msg_id"].startswith("test-")


@pytest.mark.asyncio
async def test_test_send_cross_tenant_returns_404(client, admin_jwt_headers, test_db):
    """Cross-tenant test-send returns 404 (not 403) so an endpoint id cannot be
    enumerated across tenants, and never triggers an outbound request."""
    ep = await _seed_endpoint(test_db, uuid.uuid4())   # a different tenant
    r = await client.post(f"/v1/admin/webhooks/{ep.id}/test", headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_test_send_missing_returns_404(client, admin_jwt_headers):
    r = await client.post(f"/v1/admin/webhooks/{uuid.uuid4()}/test", headers=admin_jwt_headers)
    assert r.status_code == 404


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
async def test_delete_endpoint_with_delivery_history(client, admin_jwt_headers, test_db):
    # Regression: a webhook that has ever delivered leaves rows in
    # webhook_delivery_attempts, whose FK has no ON DELETE CASCADE. Deleting the
    # endpoint must first remove that history in the same transaction, not 500
    # with a ForeignKeyViolation.
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    ep = await _seed_endpoint(test_db, tenant_id)

    test_db.add(WebhookDeliveryAttemptModel(
        id             = uuid.uuid4(),
        created_at     = datetime.utcnow(),
        endpoint_id    = ep.id,
        tenant_id      = tenant_id,
        msg_id         = "msg_" + uuid.uuid4().hex[:12],
        url            = ep.url,
        event_type     = "BLOCK",
        attempt_number = 1,
        status         = "success",
    ))
    await test_db.commit()

    r = await client.delete(f"/v1/admin/webhooks/{ep.id}", headers=admin_jwt_headers)
    assert r.status_code == 200, r.text
    assert r.json()["deleted"] is True

    assert await test_db.get(WebhookEndpointModel, ep.id) is None
    from sqlalchemy import select, func
    remaining = await test_db.scalar(
        select(func.count())
        .select_from(WebhookDeliveryAttemptModel)
        .where(WebhookDeliveryAttemptModel.endpoint_id == ep.id)
    )
    assert remaining == 0


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


# --- pause ----------------------------------------------------------

@pytest.mark.asyncio
async def test_pause_disables_a_healthy_endpoint(client, admin_jwt_headers, test_db):
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    ep = await _seed_endpoint(test_db, tenant_id)

    r = await client.post(f"/v1/admin/webhooks/{ep.id}/pause", headers=admin_jwt_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["disabled"] is True
    # A manual pause on a healthy endpoint reads as "paused", not "auto_disabled".
    assert body["status"] == "paused"
    assert body["first_failure_at"] is None


@pytest.mark.asyncio
async def test_pause_then_reactivate_round_trip(client, admin_jwt_headers, test_db):
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    ep = await _seed_endpoint(test_db, tenant_id)

    await client.post(f"/v1/admin/webhooks/{ep.id}/pause", headers=admin_jwt_headers)
    r = await client.post(f"/v1/admin/webhooks/{ep.id}/reactivate", headers=admin_jwt_headers)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active"


@pytest.mark.asyncio
async def test_circuit_breaker_disabled_reads_as_auto_disabled(client, admin_jwt_headers, test_db):
    # A disabled endpoint that carries a failure timestamp is the circuit
    # breaker's doing, not a manual pause -- it must read as auto_disabled.
    tenant_id = _tenant_id_from_headers(admin_jwt_headers)
    ep = await _seed_endpoint(
        test_db, tenant_id,
        disabled=True,
        first_failure_at=datetime(2026, 7, 1, 12, 0, 0),
    )
    r = await client.get(f"/v1/admin/webhooks/{ep.id}", headers=admin_jwt_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "auto_disabled"


@pytest.mark.asyncio
async def test_pause_cross_tenant_returns_404(client, admin_jwt_headers, test_db):
    other_tenant = uuid.uuid4()
    ep = await _seed_endpoint(test_db, other_tenant)
    r = await client.post(f"/v1/admin/webhooks/{ep.id}/pause", headers=admin_jwt_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_error_names_webhook_url_not_base_url(client, admin_jwt_headers):
    # The rejection must name the field the caller set, not the LLM validator's
    # internal "base_url".
    r = await client.post(
        "/v1/admin/webhooks",
        json={"url": "http://192.168.1.50/hook"},
        headers=admin_jwt_headers,
    )
    assert r.status_code == 422, r.text
    msg = r.json()["error"]["message"]
    assert "Webhook URL" in msg
    assert "base_url" not in msg


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
