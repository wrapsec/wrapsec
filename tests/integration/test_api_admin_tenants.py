# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Platform-operator tenant provisioning (/v1/admin/tenants).

Gated by require_platform_operator() -- the admin API key sentinel only; a tenant
ADMIN (JWT) is rejected. Covers create/list/detail, slug validation + conflict,
suspend/reactivate, and first-admin bootstrap.
"""
import uuid

import pytest

from config.settings import get_settings

settings = get_settings()


def _op():
    return {"x-api-key": settings.admin_api_key}


def _slug():
    return f"acme-{uuid.uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_create_list_detail_tenant(client):
    slug = _slug()
    r = await client.post("/v1/admin/tenants", json={"slug": slug, "name": "Acme"}, headers=_op())
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    assert r.json()["status"] == "active"

    rl = await client.get("/v1/admin/tenants", headers=_op())
    assert rl.status_code == 200
    assert any(t["id"] == tid for t in rl.json()["tenants"])

    rd = await client.get(f"/v1/admin/tenants/{tid}", headers=_op())
    assert rd.status_code == 200 and rd.json()["slug"] == slug


@pytest.mark.asyncio
async def test_duplicate_slug_conflicts(client):
    slug = _slug()
    r1 = await client.post("/v1/admin/tenants", json={"slug": slug, "name": "A"}, headers=_op())
    assert r1.status_code == 201
    r2 = await client.post("/v1/admin/tenants", json={"slug": slug, "name": "B"}, headers=_op())
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_invalid_slug_rejected(client):
    r = await client.post("/v1/admin/tenants", json={"slug": "Bad Slug!", "name": "X"}, headers=_op())
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_suspend_and_reactivate(client):
    r = await client.post("/v1/admin/tenants", json={"slug": _slug(), "name": "S"}, headers=_op())
    tid = r.json()["id"]

    rs = await client.post(f"/v1/admin/tenants/{tid}/suspend", headers=_op())
    assert rs.status_code == 200 and rs.json()["status"] == "suspended"
    assert rs.json()["suspended_at"] is not None

    rr = await client.post(f"/v1/admin/tenants/{tid}/reactivate", headers=_op())
    assert rr.status_code == 200 and rr.json()["status"] == "active"
    assert rr.json()["suspended_at"] is None


@pytest.mark.asyncio
async def test_bootstrap_first_admin_then_conflict(client):
    r = await client.post("/v1/admin/tenants", json={"slug": _slug(), "name": "B"}, headers=_op())
    tid = r.json()["id"]

    email = f"admin-{uuid.uuid4().hex[:6]}@acme-corp.com"
    rb = await client.post(
        f"/v1/admin/tenants/{tid}/bootstrap-admin",
        json={"email": email, "password": "StrongPass1!"}, headers=_op(),
    )
    assert rb.status_code == 201, rb.text
    assert rb.json()["role"] == "ADMIN"

    # A second bootstrap is refused -- the tenant already has a member.
    rb2 = await client.post(
        f"/v1/admin/tenants/{tid}/bootstrap-admin",
        json={"email": f"other-{uuid.uuid4().hex[:6]}@acme-corp.com", "password": "StrongPass1!"},
        headers=_op(),
    )
    assert rb2.status_code == 409


@pytest.mark.asyncio
async def test_bootstrap_unknown_tenant_404(client):
    rb = await client.post(
        f"/v1/admin/tenants/{uuid.uuid4()}/bootstrap-admin",
        json={"email": "x@example.com", "password": "StrongPass1!"}, headers=_op(),
    )
    assert rb.status_code == 404


@pytest.mark.asyncio
async def test_tenant_admin_is_not_platform_operator(client, auth_setup):
    """A tenant ADMIN JWT holds authority only within their tenant, never the
    control plane -- provisioning endpoints reject them (403)."""
    hdr = {"Authorization": f"Bearer {auth_setup['admin_token']}"}
    r = await client.post("/v1/admin/tenants", json={"slug": _slug(), "name": "X"}, headers=hdr)
    assert r.status_code == 403
