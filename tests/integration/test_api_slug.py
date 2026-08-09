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


@pytest.mark.asyncio
async def test_application_environment_enum_enforced(auth_client, two_tenant_setup):
    a       = two_tenant_setup["A"]
    token   = a["admin_token"]
    dept_id = str(a["dept"].id)

    # Invalid environment is rejected (not a free string anymore).
    bad = await auth_client.post(
        "/v1/admin/applications",
        json={"dept_id": dept_id, "slug": "env-bad", "name": "Env Bad", "environment": "prod"},
        headers=_auth(token),
    )
    assert bad.status_code == 422

    # A valid value in mixed case is normalized to lowercase.
    ok = await auth_client.post(
        "/v1/admin/applications",
        json={"dept_id": dept_id, "slug": "env-ok", "name": "Env OK", "environment": "Staging"},
        headers=_auth(token),
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["environment"] == "staging"


# --- Field validation hardening (email / length / enum / uuid) ---------------

@pytest.mark.asyncio
async def test_department_rejects_bad_email_and_overlong_name(auth_client, two_tenant_setup):
    token = two_tenant_setup["A"]["admin_token"]
    bad_email = await auth_client.post(
        "/v1/admin/departments",
        json={"slug": "eml", "name": "Eml", "contact_email": "not-an-email"},
        headers=_auth(token),
    )
    assert bad_email.status_code == 422
    long_name = await auth_client.post(
        "/v1/admin/departments",
        json={"slug": "lng", "name": "N" * 200},
        headers=_auth(token),
    )
    assert long_name.status_code == 422


@pytest.mark.asyncio
async def test_application_rejects_bad_owner_email(auth_client, two_tenant_setup):
    a = two_tenant_setup["A"]
    r = await auth_client.post(
        "/v1/admin/applications",
        json={"dept_id": str(a["dept"].id), "slug": "eml-app", "name": "Eml App", "owner_email": "nope"},
        headers=_auth(a["admin_token"]),
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_api_key_rejects_bad_key_type_and_bad_uuid(auth_client, two_tenant_setup):
    token = two_tenant_setup["A"]["admin_token"]
    bad_type = await auth_client.post(
        "/v1/keys",
        json={"name": "k1", "key_type": "premium"},
        headers=_auth(token),
    )
    assert bad_type.status_code == 422
    bad_uuid = await auth_client.post(
        "/v1/keys",
        json={"name": "k2", "dept_id": "not-a-uuid"},
        headers=_auth(token),
    )
    assert bad_uuid.status_code == 422


@pytest.mark.asyncio
async def test_webhook_rejects_unknown_event_type(auth_client, two_tenant_setup):
    token = two_tenant_setup["A"]["admin_token"]
    r = await auth_client.post(
        "/v1/admin/webhooks",
        json={"url": "https://example.com/hook", "event_types": ["wrapsec.request.exploded"]},
        headers=_auth(token),
    )
    assert r.status_code == 422
