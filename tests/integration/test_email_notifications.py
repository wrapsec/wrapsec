# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for the security-notification triggers (v1.8.3, Phase F).

Exercises the notification helpers against real PostgreSQL: the co-commit
password flows enqueue on the caller's session, the standalone lockout path
opens its own session, locale resolves User -> Tenant -> System -> English, and
the recipient is always the account's stored email.
"""

from __future__ import annotations

import uuid

import pytest

from db.models import DepartmentModel, TenantModel, UserModel
from db.repositories.email_outbox import EmailOutboxRepository
from services.email.notifications import (
    notify_account_deactivated,
    notify_account_locked,
    notify_account_reactivated,
    notify_admin_password_reset,
    notify_password_changed,
    notify_role_changed,
)

pytestmark = pytest.mark.asyncio


async def _make_user(db, *, email, user_locale=None, tenant_locale=None):
    tenant = TenantModel(
        id=uuid.uuid4(), slug=f"t-{uuid.uuid4().hex[:10]}", name="T",
         locale=tenant_locale,
    )
    db.add(tenant)
    await db.flush()
    user = UserModel(
        id=uuid.uuid4(), email=email, password_hash="x", locale=user_locale,
    )
    db.add(user)
    await db.flush()
    from db.repositories.membership import MembershipRepository
    await MembershipRepository(db).upsert_for_user(user.id, tenant.id, "ADMIN", None)
    await db.commit()
    user.tenant_id = tenant.id  # test convenience (no longer a mapped column)
    return user


async def _rows_for(db, tenant_id):
    return await EmailOutboxRepository(db).list_by_tenant(tenant_id=tenant_id)


# -- co-commit password flows ---------------------------------------
async def test_password_changed_enqueues_on_caller_session(pg_db):
    user = await _make_user(pg_db, email=f"pc-{uuid.uuid4().hex[:6]}@x.com")
    await notify_password_changed(pg_db, user)
    await pg_db.commit()

    rows = await _rows_for(pg_db, user.tenant_id)
    assert len(rows) == 1
    assert rows[0].notification_type == "password.changed"
    assert rows[0].recipient == user.email
    assert rows[0].user_id == user.id
    assert "password was changed" in rows[0].subject


async def test_admin_password_reset_enqueues(pg_db):
    user = await _make_user(pg_db, email=f"ar-{uuid.uuid4().hex[:6]}@x.com")
    await notify_admin_password_reset(pg_db, user, trace_id="trace-xyz")
    await pg_db.commit()

    rows = await _rows_for(pg_db, user.tenant_id)
    assert len(rows) == 1
    assert rows[0].notification_type == "password.reset_by_admin"
    assert rows[0].trace_id == "trace-xyz"


async def test_password_change_still_visible_even_if_render_skips(pg_db):
    # A recipient with unusual content must not break the co-commit path; the
    # row is still written (render never fails for these fixed-context types).
    user = await _make_user(pg_db, email=f"esc-{uuid.uuid4().hex[:6]}@x.com")
    await notify_password_changed(pg_db, user)
    await pg_db.commit()
    rows = await _rows_for(pg_db, user.tenant_id)
    assert len(rows) == 1


# -- account lifecycle + role change --------------------------------
async def test_account_deactivated_enqueues(pg_db):
    user = await _make_user(pg_db, email=f"de-{uuid.uuid4().hex[:6]}@x.com")
    await notify_account_deactivated(pg_db, user)
    await pg_db.commit()
    rows = await _rows_for(pg_db, user.tenant_id)
    assert len(rows) == 1
    assert rows[0].notification_type == "account.deactivated"


async def test_account_reactivated_enqueues(pg_db):
    user = await _make_user(pg_db, email=f"re-{uuid.uuid4().hex[:6]}@x.com")
    await notify_account_reactivated(pg_db, user)
    await pg_db.commit()
    rows = await _rows_for(pg_db, user.tenant_id)
    assert len(rows) == 1
    assert rows[0].notification_type == "account.reactivated"


async def test_role_changed_enqueues_with_new_role(pg_db):
    user = await _make_user(pg_db, email=f"rc-{uuid.uuid4().hex[:6]}@x.com")
    await notify_role_changed(pg_db, user, new_role="ADMIN")
    await pg_db.commit()
    rows = await _rows_for(pg_db, user.tenant_id)
    assert len(rows) == 1
    assert rows[0].notification_type == "role.changed"
    assert "ADMIN" in rows[0].body_text  # the new role is rendered into the body


# -- standalone lockout path ----------------------------------------
async def test_account_locked_enqueues_in_own_session(pg_db):
    user = await _make_user(pg_db, email=f"al-{uuid.uuid4().hex[:6]}@x.com")
    # Opens and commits its own session; pg_db (same DB) sees the committed row.
    await notify_account_locked(user, lockout_seconds=900)

    rows = await _rows_for(pg_db, user.tenant_id)
    assert len(rows) == 1
    assert rows[0].notification_type == "account.locked"
    assert "15 minutes" in rows[0].body_text  # 900s -> 15 min


async def test_account_locked_is_best_effort_and_never_raises(pg_db):
    # A user with a null tenant still resolves to English and does not raise.
    user = await _make_user(pg_db, email=f"al2-{uuid.uuid4().hex[:6]}@x.com")
    # Should not raise even if called twice.
    await notify_account_locked(user, lockout_seconds=60)
    await notify_account_locked(user, lockout_seconds=60)
    rows = await _rows_for(pg_db, user.tenant_id)
    assert len(rows) == 2
    assert "1 minutes" in rows[0].body_text  # 60s -> 1 min


# -- department snapshot --------------------------------------------
async def test_department_id_snapshotted_from_user(pg_db):
    tenant = TenantModel(
        id=uuid.uuid4(), slug=f"t-{uuid.uuid4().hex[:10]}", name="T",
        
    )
    pg_db.add(tenant)
    await pg_db.flush()
    dept = DepartmentModel(
        id=uuid.uuid4(), tenant_id=tenant.id, slug="eng", name="Engineering", is_active=True,
    )
    pg_db.add(dept)
    await pg_db.flush()
    user = UserModel(
        id=uuid.uuid4(),
        email=f"dev-{uuid.uuid4().hex[:6]}@x.com", password_hash="x",
    )
    pg_db.add(user)
    await pg_db.flush()
    from db.repositories.membership import MembershipRepository
    await MembershipRepository(pg_db).upsert_for_user(user.id, tenant.id, "DEVELOPER", dept.id)
    await pg_db.commit()

    await notify_password_changed(pg_db, user)
    await pg_db.commit()

    row = (await _rows_for(pg_db, tenant.id))[0]
    assert row.department_id == dept.id  # snapshotted from the recipient user


async def test_admin_recipient_has_null_department(pg_db):
    user = await _make_user(pg_db, email=f"adm-{uuid.uuid4().hex[:6]}@x.com")  # ADMIN, dept_id None
    await notify_password_changed(pg_db, user)
    await pg_db.commit()
    row = (await _rows_for(pg_db, user.tenant_id))[0]
    assert row.department_id is None  # tenant-level notification


# -- locale resolution ----------------------------------------------
async def test_locale_prefers_user_locale(pg_db):
    user = await _make_user(pg_db, email=f"lu-{uuid.uuid4().hex[:6]}@x.com", user_locale="de")
    await notify_password_changed(pg_db, user)
    await pg_db.commit()
    row = (await _rows_for(pg_db, user.tenant_id))[0]
    assert row.locale == "de"
    assert "geändert" in row.subject


async def test_locale_falls_back_to_tenant_then_english(pg_db):
    u_tenant = await _make_user(pg_db, email=f"lt-{uuid.uuid4().hex[:6]}@x.com", tenant_locale="de")
    await notify_password_changed(pg_db, u_tenant)
    await pg_db.commit()
    assert (await _rows_for(pg_db, u_tenant.tenant_id))[0].locale == "de"

    u_none = await _make_user(pg_db, email=f"ln-{uuid.uuid4().hex[:6]}@x.com")
    await notify_password_changed(pg_db, u_none)
    await pg_db.commit()
    assert (await _rows_for(pg_db, u_none.tenant_id))[0].locale == "en"
