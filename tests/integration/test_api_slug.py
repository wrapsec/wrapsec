# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Server-side slug canonicalization, uniqueness, and reserved-word guards for
department and application create endpoints."""

import pytest


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_department_slug_canonicalized_server_side(auth_client, two_tenant_setup):
    token = two_tenant_setup["A"]["admin_token"]
    r = await auth_client.post(
        "/v1/admin/departments",
        json={"slug": "Finance Dept!!", "name": "Finance"},
        headers=_auth(token),
    )
    assert r.status_code == 201, r.text
    # The client's messy slug is normalized on the server, not trusted verbatim.
    assert r.json()["slug"] == "finance-dept"


@pytest.mark.asyncio
async def test_duplicate_active_department_slug_conflicts(auth_client, two_tenant_setup):
    token = two_tenant_setup["A"]["admin_token"]
    first = await auth_client.post(
        "/v1/admin/departments",
        json={"slug": "eng-team", "name": "Engineering"},
        headers=_auth(token),
    )
    assert first.status_code == 201, first.text
    dup = await auth_client.post(
        "/v1/admin/departments",
        json={"slug": "Eng Team", "name": "Engineering Two"},  # canonicalizes to eng-team
        headers=_auth(token),
    )
    assert dup.status_code == 409
    assert dup.json()["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_reserved_department_slug_rejected(auth_client, two_tenant_setup):
    token = two_tenant_setup["A"]["admin_token"]
    r = await auth_client.post(
        "/v1/admin/departments",
        json={"slug": "default", "name": "Default"},
        headers=_auth(token),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_application_duplicate_slug_conflicts(auth_client, two_tenant_setup):
    a     = two_tenant_setup["A"]
    token = a["admin_token"]
    dept_id = str(a["dept"].id)
    first = await auth_client.post(
        "/v1/admin/applications",
        json={"dept_id": dept_id, "slug": "billing-bot", "name": "Billing Bot"},
        headers=_auth(token),
    )
    assert first.status_code == 201, first.text
    assert first.json()["slug"] == "billing-bot"
    dup = await auth_client.post(
        "/v1/admin/applications",
        json={"dept_id": dept_id, "slug": "Billing  Bot", "name": "Billing Bot 2"},
        headers=_auth(token),
    )
    assert dup.status_code == 409
    assert dup.json()["error"]["code"] == "CONFLICT"
