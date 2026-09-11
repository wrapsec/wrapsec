# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""First-run setup must close once the deployment has any user.

`POST /v1/setup` is unauthenticated and grants ADMIN of the tenant whose slug is
"default". It used to close only when THAT tenant had a membership, and three
code paths make that insufficient:

  * the default tenant is created at startup, so it exists with no memberships
    from first boot;
  * the platform-operator bootstrap route attaches an admin to an ARBITRARY
    tenant, so a deployment run through operator-provisioned tenants keeps the
    default tenant empty indefinitely;
  * nothing else ever adds a membership there.

In that state an unauthenticated caller could create a user and hand itself
ADMIN of the default tenant, at any point in the deployment's life.
"""

from __future__ import annotations

import uuid

import pytest

from db.models import MembershipModel, TenantModel, UserModel
from db.repositories.user import UserRepository
from services.auth.password import hash_password, normalize_email

_SETUP  = "/v1/setup"
_STATUS = "/v1/setup/status"


def _body() -> dict:
    return {"email": f"first-{uuid.uuid4().hex[:8]}@example.com", "password": "TestPass1!x"}


async def _user_in_another_tenant(db):
    """A user whose membership belongs to a tenant that is NOT "default".

    This is what the operator bootstrap route produces, and the state the old
    gate could not see.
    """
    tid = uuid.uuid4()
    db.add(TenantModel(id=tid, slug=f"other-{tid.hex[:8]}", name="Other"))
    await db.commit()

    user = await UserRepository(db).create({
        "email":         normalize_email(f"admin-{uuid.uuid4().hex[:8]}@example.com"),
        "password_hash": hash_password("TestPass1!x"),
    })
    await UserRepository(db).flush()
    db.add(MembershipModel(id=uuid.uuid4(), user_id=user.id, tenant_id=tid,
                           role="ADMIN", dept_id=None))
    await db.commit()
    return user


@pytest.mark.asyncio
async def test_setup_is_refused_once_a_user_exists_in_another_tenant(client, test_db):
    """The exposure. The default tenant still has no membership, so the old gate
    let this through and handed out ADMIN of it."""
    await _user_in_another_tenant(test_db)

    resp = await client.post(_SETUP, json=_body())

    assert resp.status_code == 404, (
        f"setup answered {resp.status_code} while the deployment already had a "
        "user: an unauthenticated caller was able to create an admin"
    )


@pytest.mark.asyncio
async def test_no_user_was_created_by_the_refused_attempt(client, test_db):
    """A refusal that still wrote the row would be worse than none.

    Asserted on THIS request's own email rather than on a total row count. A
    count is sensitive to whatever else has run: an earlier test that opened and
    then closed the gate leaves the count unchanged for the wrong reason, and
    the assertion passes while proving nothing about this request.
    """
    from sqlalchemy import select

    await _user_in_another_tenant(test_db)

    body = _body()
    await client.post(_SETUP, json=body)

    created = await test_db.scalar(
        select(UserModel.id).where(UserModel.email == normalize_email(body["email"]))
    )
    assert created is None, (
        "the refused setup attempt still created the user it was asked for"
    )


@pytest.mark.asyncio
async def test_status_agrees_with_the_gate(client, test_db):
    """If these disagreed, the dashboard would offer a setup page the route
    refuses, or hide one it would still serve."""
    await _user_in_another_tenant(test_db)

    status = await client.get(_STATUS)

    assert status.status_code == 200
    assert status.json()["initialized"] is True, (
        "status reports an uninitialized system while a user exists, so it "
        "disagrees with the route that would refuse the request"
    )


@pytest.mark.asyncio
async def test_a_genuinely_empty_deployment_can_still_run_setup(client, test_db):
    """The control. A gate that refused everything would satisfy the tests above
    and make first-run setup impossible."""
    from sqlalchemy import delete

    from db.models import AdminEventModel, RefreshTokenModel

    # `admin_events` references `users` without a cascade, so it must go first;
    # memberships and refresh tokens cascade.
    await test_db.execute(delete(AdminEventModel))
    await test_db.execute(delete(RefreshTokenModel))
    await test_db.execute(delete(MembershipModel))
    await test_db.execute(delete(UserModel))
    await test_db.commit()

    resp = await client.post(_SETUP, json=_body())

    assert resp.status_code in (200, 201), (
        f"a deployment with no users at all could not run setup: {resp.status_code} "
        f"{resp.text[:200]}"
    )
