# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Audit-trail completeness: auth actions write auth_events and admin actions write
admin_events. Ported from the retired manual tests/scripts/validate_e2e.ps1
(sections 6 + 14) -- those flows are exercised elsewhere, but nothing else
asserts the event ROWS (other tests only clean these tables up).

Fixtures (auth_client, auth_setup) come from conftest.py.
"""
import uuid

import pytest
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from config.settings import get_settings
from db.models import AdminEventModel, AuthEventModel, RefreshTokenModel, UserModel

settings = get_settings()


def _sessionmaker():
    """A private NullPool session for reading/cleaning event rows (same pattern
    as auth_setup and the admin-user tests)."""
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    return engine, async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@pytest.mark.asyncio
async def test_login_success_and_failures_write_auth_events(auth_client, auth_setup):
    """A successful login, a wrong password, and an unknown user each write the
    correct auth_events row (action + success + failure_reason)."""
    admin = auth_setup["admin_user"]

    r = await auth_client.post("/v1/auth/login",
                               json={"email": admin.email, "password": "TestPass1!"})
    assert r.status_code == 200

    r = await auth_client.post("/v1/auth/login",
                               json={"email": admin.email, "password": "WrongPass9!"})
    assert r.status_code == 401

    unknown = f"nobody-{uuid.uuid4().hex[:6]}@test.com"
    r = await auth_client.post("/v1/auth/login",
                               json={"email": unknown, "password": "WhatEver1!"})
    assert r.status_code == 401

    engine, sf = _sessionmaker()
    try:
        async with sf() as db:
            # Success + wrong-password are attributed to the admin user.
            known = (await db.execute(
                select(AuthEventModel).where(AuthEventModel.user_id == admin.id)
            )).scalars().all()
            seen = {(e.action, e.success, e.failure_reason) for e in known}
            assert ("login_success", True, None) in seen
            assert ("login_failed", False, "invalid_password") in seen

            # Unknown user: attributed to no user, enumeration-safe reason.
            nf = (await db.execute(
                select(AuthEventModel).where(
                    AuthEventModel.user_id.is_(None),
                    AuthEventModel.action == "login_failed",
                    AuthEventModel.failure_reason == "user_not_found",
                )
            )).scalars().all()
            assert len(nf) >= 1

            # Cleanup the rows this test produced.
            await db.execute(sa_delete(AuthEventModel).where(AuthEventModel.user_id == admin.id))
            await db.execute(sa_delete(AuthEventModel).where(
                AuthEventModel.user_id.is_(None),
                AuthEventModel.action == "login_failed",
                AuthEventModel.failure_reason == "user_not_found",
            ))
            await db.commit()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_admin_actions_write_admin_events(auth_client, auth_setup):
    """Create / role-change / reset-password each write the correct admin_events
    row, and role_changed carries the previous role in metadata."""
    hdr       = {"Authorization": f"Bearer {auth_setup['admin_token']}"}
    dept_id   = str(auth_setup["dept"].id)
    new_email = f"audit-{uuid.uuid4().hex[:6]}@test.com"

    r = await auth_client.post("/v1/admin/users", headers=hdr,
        json={"email": new_email, "password": "TempPass1!", "role": "DEVELOPER", "dept_id": dept_id})
    assert r.status_code == 201
    uid = uuid.UUID(r.json()["id"])

    r = await auth_client.patch(f"/v1/admin/users/{uid}", headers=hdr, json={"role": "VIEWER"})
    assert r.status_code == 200

    r = await auth_client.post(f"/v1/admin/users/{uid}/reset-password", headers=hdr,
                               json={"new_password": "NewTemp1!"})
    assert r.status_code == 200

    engine, sf = _sessionmaker()
    try:
        async with sf() as db:
            rows = (await db.execute(
                select(AdminEventModel).where(AdminEventModel.target_user_id == uid)
            )).scalars().all()
            actions = {e.action for e in rows}
            assert {"user_created", "role_changed", "password_reset"} <= actions

            role_changed = next(e for e in rows if e.action == "role_changed")
            assert role_changed.metadata_ == {"old_role": "DEVELOPER", "new_role": "VIEWER"}

            await db.execute(sa_delete(AdminEventModel).where(AdminEventModel.target_user_id == uid))
            await db.execute(sa_delete(RefreshTokenModel).where(RefreshTokenModel.user_id == uid))
            await db.execute(sa_delete(UserModel).where(UserModel.id == uid))
            await db.commit()
    finally:
        await engine.dispose()
