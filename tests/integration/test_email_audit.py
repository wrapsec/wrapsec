# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for the email audit endpoints (v1.8.3, Phase G).

Covers interim RBAC (Admin and Auditor may read; Developer/Viewer/API key are
rejected), strict tenant scoping (an admin never sees another tenant's rows),
and the 404-on-cross-tenant-id behavior.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from config.settings import get_settings
from db.models import EmailOutboxModel, SettingsModel, TenantModel, UserModel
from db.repositories.email_outbox import EmailOutboxRepository
from services.auth.token import create_access_token
from services.time import utc_now
from services.webhooks.retry_schedule import MAX_ATTEMPTS, RETRY_SCHEDULE_SECONDS

pytestmark = pytest.mark.asyncio

settings = get_settings()


def _sf():
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    return engine, async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def email_seeder():
    """Seed email_outbox rows (creating any foreign tenant they need to satisfy
    the tenant FK) and delete both on teardown -- before auth_setup removes its
    own tenant, so no FK is ever violated."""
    created_emails:  list[uuid.UUID] = []
    created_tenants: list[uuid.UUID] = []

    async def seed(*, tenant_id, user_id=None, status="provider_accepted", recipient="x@x.com",
                   notification_type="password.changed"):
        rid = uuid.uuid4()
        engine, sf = _sf()
        try:
            async with sf() as db:
                # Ensure the tenant exists (FK). Track only tenants we create so
                # we do not delete auth_setup's tenant on teardown.
                if await db.get(TenantModel, tenant_id) is None:
                    db.add(TenantModel(
                        id=tenant_id, slug=f"seed-{tenant_id.hex[:10]}", name="Seed",
                        global_policy={}, is_active=True,
                    ))
                    created_tenants.append(tenant_id)
                    await db.flush()
                db.add(EmailOutboxModel(
                    id=rid, tenant_id=tenant_id, user_id=user_id,
                    notification_type=notification_type, recipient=recipient, locale="en",
                    subject="Your WrapSec password was changed", body_text="t", body_html="<p>t</p>",
                    status=status, attempt_count=1, available_at=utc_now(), created_at=utc_now(),
                ))
                await db.commit()
        finally:
            await engine.dispose()
        created_emails.append(rid)
        return rid

    yield seed

    engine, sf = _sf()
    try:
        async with sf() as db:
            if created_emails:
                await db.execute(sa_delete(EmailOutboxModel).where(EmailOutboxModel.id.in_(created_emails)))
            if created_tenants:
                await db.execute(sa_delete(TenantModel).where(TenantModel.id.in_(created_tenants)))
            await db.commit()
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def reset_email_settings():
    """email_settings is a single global row; delete it on teardown so a
    mutating test cannot leak (e.g. notifications=off) into other tests."""
    yield
    engine, sf = _sf()
    try:
        async with sf() as db:
            await db.execute(sa_delete(SettingsModel).where(SettingsModel.key == "email_settings"))
            await db.commit()
    finally:
        await engine.dispose()


async def _make_auditor(tenant_id) -> str:
    """Create a real AUDITOR user (the middleware resolves role from the DB) and
    return a signed access token. Cleaned up by auth_setup's tenant-user delete."""
    uid = uuid.uuid4()
    engine, sf = _sf()
    try:
        async with sf() as db:
            db.add(UserModel(
                id=uid, tenant_id=tenant_id, dept_id=None,
                email=f"auditor-{uuid.uuid4().hex[:6]}@test.com", password_hash="x",
                role="AUDITOR", token_version=1,
            ))
            await db.commit()
    finally:
        await engine.dispose()
    m = MagicMock()
    m.id = uid; m.tenant_id = tenant_id; m.dept_id = None; m.role = "AUDITOR"; m.token_version = 1
    return create_access_token(m)


# -- RBAC ------------------------------------------------------------
async def test_admin_can_list_email_audit(auth_client, auth_setup, email_seeder):
    tid = auth_setup["tenant"].id
    await email_seeder(tenant_id=tid, recipient="a@x.com")

    resp = await auth_client.get(
        "/v1/admin/email", headers={"Authorization": f"Bearer {auth_setup['admin_token']}"}
    )
    assert resp.status_code == 200
    emails = resp.json()["emails"]
    assert any(e["recipient"] == "a@x.com" for e in emails)
    # Bodies must NOT be exposed by the audit view.
    assert all("body_text" not in e and "body_html" not in e for e in emails)


async def test_auditor_can_list_email_audit(auth_client, auth_setup, email_seeder):
    tid = auth_setup["tenant"].id
    await email_seeder(tenant_id=tid, recipient="b@x.com")
    auditor_token = await _make_auditor(tid)

    resp = await auth_client.get(
        "/v1/admin/email", headers={"Authorization": f"Bearer {auditor_token}"}
    )
    assert resp.status_code == 200


async def test_developer_cannot_read_email_audit(auth_client, auth_setup):
    resp = await auth_client.get(
        "/v1/admin/email", headers={"Authorization": f"Bearer {auth_setup['dev_token']}"}
    )
    assert resp.status_code == 403


async def test_viewer_cannot_read_email_audit(auth_client, auth_setup):
    resp = await auth_client.get(
        "/v1/admin/email", headers={"Authorization": f"Bearer {auth_setup['viewer_token']}"}
    )
    assert resp.status_code == 403


async def test_api_key_cannot_read_email_audit(auth_client, auth_setup):
    resp = await auth_client.get("/v1/admin/email", headers={"x-api-key": settings.admin_api_key})
    assert resp.status_code == 403


# -- tenant scoping --------------------------------------------------
async def test_admin_sees_only_own_tenant_emails(auth_client, auth_setup, email_seeder):
    own_tid   = auth_setup["tenant"].id
    other_tid = uuid.uuid4()  # a tenant the admin does not belong to
    await email_seeder(tenant_id=own_tid, recipient="own@x.com")
    await email_seeder(tenant_id=other_tid, recipient="foreign@x.com")

    resp = await auth_client.get(
        "/v1/admin/email", headers={"Authorization": f"Bearer {auth_setup['admin_token']}"}
    )
    assert resp.status_code == 200
    recipients = {e["recipient"] for e in resp.json()["emails"]}
    assert "own@x.com" in recipients
    assert "foreign@x.com" not in recipients


async def test_get_email_cross_tenant_is_404(auth_client, auth_setup, email_seeder):
    other_tid = uuid.uuid4()
    foreign_id = await email_seeder(tenant_id=other_tid, recipient="foreign@x.com")

    resp = await auth_client.get(
        f"/v1/admin/email/{foreign_id}",
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    assert resp.status_code == 404


async def test_get_email_own_tenant_ok(auth_client, auth_setup, email_seeder):
    tid = auth_setup["tenant"].id
    rid = await email_seeder(tenant_id=tid, recipient="mine@x.com")

    resp = await auth_client.get(
        f"/v1/admin/email/{rid}",
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    assert resp.status_code == 200
    assert resp.json()["recipient"] == "mine@x.com"


async def test_invalid_status_filter_rejected(auth_client, auth_setup):
    resp = await auth_client.get(
        "/v1/admin/email?status=bogus",
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    assert resp.status_code == 400


# -- summary + filters ----------------------------------------------
async def test_summary_counts_by_status(auth_client, auth_setup, email_seeder):
    tid = auth_setup["tenant"].id
    await email_seeder(tenant_id=tid, status="provider_accepted", recipient="s1@x.com")
    await email_seeder(tenant_id=tid, status="provider_accepted", recipient="s2@x.com")
    await email_seeder(tenant_id=tid, status="failed", recipient="s3@x.com")

    resp = await auth_client.get(
        "/v1/admin/email/summary",
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    assert resp.status_code == 200
    counts = resp.json()["counts"]
    # Every status key is present (zero-filled), and our seeds are reflected.
    assert set(counts) == {"queued", "sending", "provider_accepted", "failed"}
    assert counts["provider_accepted"] >= 2
    assert counts["failed"] >= 1


async def test_filter_by_status(auth_client, auth_setup, email_seeder):
    tid = auth_setup["tenant"].id
    await email_seeder(tenant_id=tid, status="failed", recipient="f1@x.com")
    await email_seeder(tenant_id=tid, status="provider_accepted", recipient="ok1@x.com")

    resp = await auth_client.get(
        "/v1/admin/email?status=failed",
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    assert resp.status_code == 200
    statuses = {e["status"] for e in resp.json()["emails"]}
    assert statuses == {"failed"}


async def test_filter_by_recipient_substring(auth_client, auth_setup, email_seeder):
    tid = auth_setup["tenant"].id
    await email_seeder(tenant_id=tid, recipient="alice@needle.com")
    await email_seeder(tenant_id=tid, recipient="bob@haystack.com")

    resp = await auth_client.get(
        "/v1/admin/email?recipient=needle",
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    assert resp.status_code == 200
    recipients = [e["recipient"] for e in resp.json()["emails"]]
    assert recipients == ["alice@needle.com"]


async def test_filter_by_notification_type(auth_client, auth_setup, email_seeder):
    tid = auth_setup["tenant"].id
    await email_seeder(tenant_id=tid, notification_type="account.locked", recipient="al@x.com")
    await email_seeder(tenant_id=tid, notification_type="password.changed", recipient="pc@x.com")

    resp = await auth_client.get(
        "/v1/admin/email?notification_type=account.locked",
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    assert resp.status_code == 200
    types = {e["notification_type"] for e in resp.json()["emails"]}
    assert types == {"account.locked"}


async def test_list_omits_subject_and_body(auth_client, auth_setup, email_seeder):
    tid = auth_setup["tenant"].id
    await email_seeder(tenant_id=tid, recipient="meta@x.com")
    resp = await auth_client.get(
        "/v1/admin/email?recipient=meta",
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    e = resp.json()["emails"][0]
    for forbidden in ("subject", "body_text", "body_html"):
        assert forbidden not in e
    # doc field vocabulary is present
    for field in ("last_attempt_at", "completed_at", "department_id"):
        assert field in e


async def test_bad_created_from_rejected(auth_client, auth_setup):
    resp = await auth_client.get(
        "/v1/admin/email?created_from=not-a-date",
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    assert resp.status_code == 400


# -- trigger wiring (endpoint -> outbox) ----------------------------
async def test_deactivate_user_endpoint_enqueues_notification(auth_client, auth_setup):
    # Deactivate the viewer as admin; the update_user endpoint should enqueue an
    # account.deactivated notification co-committed with the change.
    viewer_id = str(auth_setup["viewer_user"].id)
    tid = auth_setup["tenant"].id
    resp = await auth_client.patch(
        f"/v1/admin/users/{viewer_id}",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
    )
    assert resp.status_code == 200

    engine, sf = _sf()
    try:
        async with sf() as db:
            rows = await EmailOutboxRepository(db).list_by_tenant(tenant_id=tid)
            assert any(
                r.notification_type == "account.deactivated" and str(r.user_id) == viewer_id
                for r in rows
            )
            # Clean the outbox rows so auth_setup can delete the tenant (FK).
            await db.execute(sa_delete(EmailOutboxModel).where(EmailOutboxModel.tenant_id == tid))
            await db.commit()
    finally:
        await engine.dispose()


# -- settings API ---------------------------------------------------
def _admin(auth_setup):
    return {"Authorization": f"Bearer {auth_setup['admin_token']}"}


async def test_get_settings_returns_defaults_and_real_schedule(auth_client, auth_setup):
    resp = await auth_client.get("/v1/admin/email/settings", headers=_admin(auth_setup))
    assert resp.status_code == 200
    body = resp.json()
    assert body["notifications_enabled"] is True
    assert body["max_attempts"] == MAX_ATTEMPTS
    assert body["retention_days"] >= 1
    # Retry policy is served from the REAL schedule, read-only.
    assert body["retry_schedule"]["intervals_seconds"] == list(RETRY_SCHEDULE_SECONDS)
    assert body["retry_schedule"]["max_attempts_ceiling"] == MAX_ATTEMPTS
    assert body["retry_schedule"]["min_attempts"] == 1


async def test_put_settings_roundtrip(auth_client, auth_setup, reset_email_settings):
    put = await auth_client.put(
        "/v1/admin/email/settings",
        json={"notifications_enabled": False, "max_attempts": 3, "retention_days": 7},
        headers=_admin(auth_setup),
    )
    assert put.status_code == 200
    assert put.json()["max_attempts"] == 3

    got = await auth_client.get("/v1/admin/email/settings", headers=_admin(auth_setup))
    body = got.json()
    assert body["notifications_enabled"] is False
    assert body["max_attempts"] == 3
    assert body["retention_days"] == 7


async def test_put_settings_rejects_max_above_ceiling(auth_client, auth_setup, reset_email_settings):
    resp = await auth_client.put(
        "/v1/admin/email/settings",
        json={"notifications_enabled": True, "max_attempts": MAX_ATTEMPTS + 1, "retention_days": 30},
        headers=_admin(auth_setup),
    )
    assert resp.status_code == 400


async def test_put_settings_rejects_zero_retention(auth_client, auth_setup, reset_email_settings):
    resp = await auth_client.put(
        "/v1/admin/email/settings",
        json={"notifications_enabled": True, "max_attempts": 3, "retention_days": 0},
        headers=_admin(auth_setup),
    )
    assert resp.status_code == 400


async def test_auditor_cannot_change_settings(auth_client, auth_setup):
    auditor_token = await _make_auditor(auth_setup["tenant"].id)
    # Auditor may read the delivery audit but not the system email settings.
    get_resp = await auth_client.get(
        "/v1/admin/email/settings", headers={"Authorization": f"Bearer {auditor_token}"}
    )
    assert get_resp.status_code == 403
    put_resp = await auth_client.put(
        "/v1/admin/email/settings",
        json={"notifications_enabled": True, "max_attempts": 3, "retention_days": 30},
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert put_resp.status_code == 403


async def test_developer_cannot_change_settings(auth_client, auth_setup):
    resp = await auth_client.get(
        "/v1/admin/email/settings",
        headers={"Authorization": f"Bearer {auth_setup['dev_token']}"},
    )
    assert resp.status_code == 403


async def test_notifications_off_skips_enqueue(auth_client, auth_setup, reset_email_settings):
    # Turn notifications off, then a trigger enqueue is skipped.
    await auth_client.put(
        "/v1/admin/email/settings",
        json={"notifications_enabled": False, "max_attempts": 8, "retention_days": 30},
        headers=_admin(auth_setup),
    )

    from services.email.notifications import notify_password_changed

    tenant_id = auth_setup["tenant"].id
    engine, sf = _sf()
    try:
        async with sf() as db:
            uid = uuid.uuid4()
            db.add(UserModel(
                id=uid, tenant_id=tenant_id, dept_id=None,
                email=f"off-{uuid.uuid4().hex[:6]}@x.com", password_hash="x", role="ADMIN",
            ))
            await db.commit()
            user = await db.get(UserModel, uid)
            await notify_password_changed(db, user)
            await db.commit()
            rows = await EmailOutboxRepository(db).list_by_tenant(tenant_id=tenant_id)
            assert rows == []  # nothing enqueued while notifications are off
            await db.execute(sa_delete(UserModel).where(UserModel.id == uid))
            await db.commit()
    finally:
        await engine.dispose()
