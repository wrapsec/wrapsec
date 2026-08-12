# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Issue 162 regression: HTTP-boundary cross-tenant isolation.

Repo-layer tests live in tests/unit/db/repositories/test_cross_tenant_isolation.py
and prove that every tenant-scoped repository method filters by tenant_id.
These tests exercise the same guarantee at the HTTP layer: a request
authenticated as tenant A's admin must never access tenant B's resource by
ID via any endpoint.

Expected response for cross-tenant lookup is 404 (masking) rather than 403,
so probing for existence does not leak the fact that another tenant owns
the ID.
"""
import uuid
import pytest


# ── API Keys ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_key_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/keys/{b['api_key_id']}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_key_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.put(
        f"/v1/keys/{b['api_key_id']}",
        json={"name": "hijacked"},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_key_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.delete(
        f"/v1/keys/{b['api_key_id']}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_rotate_key_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.post(
        f"/v1/keys/{b['api_key_id']}/rotate",
        json={},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_keys_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/keys",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    key_ids = {k["key_id"] for k in response.json().get("keys", [])}
    assert a["api_key_id"] in key_ids
    assert b["api_key_id"] not in key_ids


# ── Departments ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_department_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/departments/{b['dept'].id}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_department_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.put(
        f"/v1/admin/departments/{b['dept'].id}",
        json={"name": "hijacked"},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_department_stats_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/departments/{b['dept'].id}/stats",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_department_policy_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/departments/{b['dept'].id}/policy",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_departments_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/admin/departments",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    dept_ids = {d["id"] for d in response.json().get("departments", [])}
    assert str(a["dept"].id) in dept_ids
    assert str(b["dept"].id) not in dept_ids


# ── Applications ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_application_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/applications/{b['app'].id}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_application_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.put(
        f"/v1/admin/applications/{b['app'].id}",
        json={"name": "hijacked"},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_application_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.delete(
        f"/v1/admin/applications/{b['app'].id}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_application_policy_get_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/applications/{b['app'].id}/policy",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_application_policy_put_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.put(
        f"/v1/admin/applications/{b['app'].id}/policy",
        json={"policy_override": {}},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_applications_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/admin/applications",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    app_ids = {app["id"] for app in response.json().get("applications", [])}
    assert str(a["app"].id) in app_ids
    assert str(b["app"].id) not in app_ids


# ── Users (admin endpoints) ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_user_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/admin/users/{b['admin_user'].id}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_patch_user_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.patch(
        f"/v1/admin/users/{b['admin_user'].id}",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_users_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/admin/users",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    user_ids = {u["id"] for u in response.json().get("users", [])}
    assert str(a["admin_user"].id) in user_ids
    assert str(b["admin_user"].id) not in user_ids


# ── Audit trace-id lookup (ai.py /v1/ai/requests/{trace_id}) ────────────────

@pytest.mark.asyncio
async def test_get_request_by_trace_cross_tenant_returns_404(auth_client, two_tenant_setup):
    """
    /v1/ai/requests/{trace_id} routes through get_scoped_audit_record. An admin
    of tenant A must not be able to fetch tenant B's audit record by trace_id.
    """
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        f"/v1/ai/requests/{b['audit_trace']}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 404


# ── Audit Logs ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_logs_scoped_to_own_tenant(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    response = await auth_client.get(
        "/v1/audit/logs",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json().get("items", [])}
    assert a["audit_trace"] in trace_ids
    assert b["audit_trace"] not in trace_ids


# ── Nonexistent-ID sanity check ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nonexistent_ids_also_return_404(auth_client, two_tenant_setup):
    """
    Sanity check that a random UUID returns 404 the same way a cross-tenant
    UUID does. This confirms the guard is masking, not distinguishing between
    "does not exist" and "belongs to another tenant".
    """
    a = two_tenant_setup["A"]
    fake = uuid.uuid4()
    for path in (
        f"/v1/departments/{fake}",
        f"/v1/applications/{fake}",
        f"/v1/admin/users/{fake}",
    ):
        response = await auth_client.get(
            path,
            headers={"Authorization": f"Bearer {a['admin_token']}"},
        )
        assert response.status_code == 404, f"{path} returned {response.status_code}"


# ── Webhooks (v1.3.0) ────────────────────────────────────────────────────────

async def _create_webhook_for(auth_client, tok: str) -> str:
    resp = await auth_client.post(
        "/v1/admin/webhooks",
        json={"url": "https://example.com/hook"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code in (200, 201), f"webhook create failed: {resp.status_code} {resp.text}"
    body = resp.json()
    return body.get("id") or body["endpoint_id"]


@pytest.mark.asyncio
async def test_delete_webhook_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    wid = await _create_webhook_for(auth_client, b["admin_token"])
    # Tenant A's admin must not delete tenant B's webhook.
    resp = await auth_client.delete(
        f"/v1/admin/webhooks/{wid}",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert resp.status_code == 404
    # Cleanup as the owner.
    await auth_client.delete(
        f"/v1/admin/webhooks/{wid}",
        headers={"Authorization": f"Bearer {b['admin_token']}"},
    )


@pytest.mark.asyncio
async def test_pause_webhook_cross_tenant_returns_404(auth_client, two_tenant_setup):
    a, b = two_tenant_setup["A"], two_tenant_setup["B"]
    wid = await _create_webhook_for(auth_client, b["admin_token"])
    resp = await auth_client.post(
        f"/v1/admin/webhooks/{wid}/pause",
        headers={"Authorization": f"Bearer {a['admin_token']}"},
    )
    assert resp.status_code == 404
    await auth_client.delete(
        f"/v1/admin/webhooks/{wid}",
        headers={"Authorization": f"Bearer {b['admin_token']}"},
    )
