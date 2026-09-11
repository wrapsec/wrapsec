# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Probing for an address in another tenant leaves a trail.

`users.email` is unique across the deployment, so creating a user with an
address already registered ANYWHERE fails -- including in a tenant the
administrator cannot see. The 409 is truthful and unavoidable: identity is
global here, so any create attempt necessarily reveals whether an address is
taken, and a response that concealed it would have to lie or claim a success
that did not happen.

It is therefore made DETECTABLE rather than deniable. An administrator sweeping
addresses leaves one audit row per probe, proportional to the sweep, and the
endpoint is rate limited besides.

Login itself is uniform and leaks nothing; this is the narrower oracle available
only to an already-authenticated administrator.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from db.models import AdminEventModel

_CREATE = "/v1/admin/users"


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_a_probe_for_a_cross_tenant_address_is_recorded(
    client, auth_setup, two_tenant_setup, test_db,
):
    """The administrator of one tenant probes an address that exists only in
    another. The refusal is unchanged; the record is what is new."""
    other_email = two_tenant_setup["B"]["admin_user"].email

    resp = await client.post(
        _CREATE,
        json={"email": other_email, "password": "TestPass1!x", "role": "VIEWER",
              "dept_id": str(auth_setup["dept"].id)},
        headers=_bearer(auth_setup["admin_token"]),
    )

    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "CONFLICT"

    recorded = await test_db.scalar(
        select(AdminEventModel.action).where(
            AdminEventModel.action == "user_create_rejected_existing_email",
            AdminEventModel.tenant_id == auth_setup["tenant"].id,
        )
    )
    assert recorded == "user_create_rejected_existing_email", (
        "an administrator learned that an address is registered elsewhere and "
        "nothing recorded that they asked"
    )


@pytest.mark.asyncio
async def test_the_refusal_still_says_nothing_about_where(client, auth_setup, two_tenant_setup):
    """Detectability is the mitigation; the response must not become MORE
    informative in the process. It must not name the tenant, the user, or
    anything beyond the fact the address is taken."""
    other = two_tenant_setup["B"]["admin_user"]

    resp = await client.post(
        _CREATE,
        json={"email": other.email, "password": "TestPass1!x", "role": "VIEWER",
              "dept_id": str(auth_setup["dept"].id)},
        headers=_bearer(auth_setup["admin_token"]),
    )

    body = resp.text
    assert str(other.id) not in body, "the refusal disclosed the user id"
    assert str(two_tenant_setup["B"]["tenant"].id) not in body, (
        "the refusal disclosed which tenant holds the address"
    )


@pytest.mark.asyncio
async def test_a_successful_create_is_not_recorded_as_a_probe(client, auth_setup, test_db):
    """The control. An event written on every create would make the probe
    record meaningless -- it has to mark the refusal specifically."""
    fresh = f"fresh-{uuid.uuid4().hex[:8]}@example.com"

    resp = await client.post(
        _CREATE,
        json={"email": fresh, "password": "TestPass1!x", "role": "VIEWER",
              "dept_id": str(auth_setup["dept"].id)},
        headers=_bearer(auth_setup["admin_token"]),
    )
    assert resp.status_code in (200, 201), resp.text

    probes = (await test_db.execute(
        select(AdminEventModel.id).where(
            AdminEventModel.action == "user_create_rejected_existing_email",
            AdminEventModel.tenant_id == auth_setup["tenant"].id,
        )
    )).all()
    assert not probes, "a successful create was recorded as a probe"
