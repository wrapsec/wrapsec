# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for the outbox email delivery worker (v1.8.3, Phase D).

Exercises the real PostgreSQL claim/send/record cycle: atomic claim with
SELECT ... FOR UPDATE SKIP LOCKED, provider_accepted on success, transient
reschedule, permanent failure, retry exhaustion, and concurrent-claim
disjointness. Uses the in-memory FakeEmailProvider so no SMTP server is touched.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from db.repositories.email_outbox import EmailOutboxRepository
from domain.enums import EmailStatus, NotificationType
from services.email.fake_provider import FakeEmailProvider
from services.email.service import EmailService
from services.time import utc_now
from workers import email_delivery

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def sf(_pg_engine):
    """Session factory on the disposable test engine, with a clean outbox."""
    factory = async_sessionmaker(bind=_pg_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as db:
        await db.execute(text("TRUNCATE TABLE email_outbox"))
        await db.commit()
    return factory


async def _enqueue(sf, nt, recipient, context, *, commit=True):
    async with sf() as db:
        row = await EmailService().queue(
            db, notification_type=nt, recipient=recipient, locale="en", context=context
        )
        if commit:
            await db.commit()
        return row.id


def _ctx(**over):
    base = {"display_name": "user@example.com", "event_time": "2026-08-12T10:00:00Z"}
    base.update(over)
    return base


async def _status(sf, row_id):
    async with sf() as db:
        row = await EmailOutboxRepository(db).get_by_id(row_id)
        return row


# -- happy path ------------------------------------------------------
async def test_worker_delivers_and_marks_accepted(sf):
    rid = await _enqueue(sf, NotificationType.PASSWORD_CHANGED, "a@x.com", _ctx())
    provider = FakeEmailProvider()

    claimed = await email_delivery._claim(sf, batch=10)
    assert len(claimed) == 1
    await email_delivery._process_one(sf, provider, "no-reply@wrapsec.com", "WrapSec", claimed[0], asyncio.Semaphore(1))

    assert len(provider.sent) == 1
    assert provider.sent[0].to_addr == "a@x.com"
    row = await _status(sf, rid)
    assert row.status == EmailStatus.PROVIDER_ACCEPTED.value
    assert row.attempt_count == 1
    assert row.sent_at is not None
    assert row.provider_message_id and str(rid) in row.provider_message_id  # stable id from row id


# -- transient reschedule -------------------------------------------
async def test_transient_failure_reschedules(sf):
    rid = await _enqueue(sf, NotificationType.PASSWORD_CHANGED, "a@x.com", _ctx())
    provider = FakeEmailProvider()
    provider.fail_next = "transient"

    claimed = await email_delivery._claim(sf, batch=10)
    await email_delivery._process_one(sf, provider, "no-reply@wrapsec.com", "WrapSec", claimed[0], asyncio.Semaphore(1))

    row = await _status(sf, rid)
    assert row.status == EmailStatus.QUEUED.value
    assert row.attempt_count == 1
    assert row.available_at > utc_now()  # pushed into the future
    assert "transient" in (row.last_error or "")


# -- permanent failure ----------------------------------------------
async def test_permanent_failure_marks_failed(sf):
    rid = await _enqueue(sf, NotificationType.PASSWORD_CHANGED, "a@x.com", _ctx())
    provider = FakeEmailProvider()
    provider.fail_next = "permanent"

    claimed = await email_delivery._claim(sf, batch=10)
    await email_delivery._process_one(sf, provider, "no-reply@wrapsec.com", "WrapSec", claimed[0], asyncio.Semaphore(1))

    row = await _status(sf, rid)
    assert row.status == EmailStatus.FAILED.value
    assert row.attempt_count == 1
    assert "permanent" in (row.last_error or "")


# -- retry exhaustion -----------------------------------------------
async def test_retry_exhaustion_marks_failed(sf):
    from services.webhooks.retry_schedule import MAX_ATTEMPTS

    rid = await _enqueue(sf, NotificationType.PASSWORD_CHANGED, "a@x.com", _ctx())
    # Fast-forward attempt_count to the last allowed attempt so the next
    # transient failure exhausts the schedule.
    async with sf() as db:
        row = await EmailOutboxRepository(db).get_by_id(rid)
        row.attempt_count = MAX_ATTEMPTS - 1
        await db.commit()

    provider = FakeEmailProvider()
    provider.fail_next = "transient"
    claimed = await email_delivery._claim(sf, batch=10)
    await email_delivery._process_one(sf, provider, "no-reply@wrapsec.com", "WrapSec", claimed[0], asyncio.Semaphore(1))

    row = await _status(sf, rid)
    assert row.status == EmailStatus.FAILED.value
    assert row.attempt_count == MAX_ATTEMPTS
    assert "exhausted" in (row.last_error or "")


# -- concurrent claim disjointness (SKIP LOCKED) --------------------
async def test_concurrent_claims_are_disjoint(sf):
    await _enqueue(sf, NotificationType.PASSWORD_CHANGED, "a@x.com", _ctx())
    await _enqueue(sf, NotificationType.PASSWORD_CHANGED, "b@x.com", _ctx())

    # Session A claims one row and holds its transaction open (lock held).
    async with sf() as db_a:
        repo_a = EmailOutboxRepository(db_a)
        claimed_a = await repo_a.claim_batch(limit=1)
        assert len(claimed_a) == 1

        # Session B claims concurrently: SKIP LOCKED must skip A's locked row.
        async with sf() as db_b:
            claimed_b = await EmailOutboxRepository(db_b).claim_batch(limit=10)
            await db_b.commit()

        assert len(claimed_b) == 1
        assert {c.id for c in claimed_a}.isdisjoint({c.id for c in claimed_b})
        await db_a.commit()


# -- retention -------------------------------------------------------
async def test_retention_deletes_old_rows_keeps_recent(sf):
    import uuid
    from datetime import timedelta

    from db.models import EmailOutboxModel
    from workers.tasks import _cleanup_email_outbox

    recent_id = uuid.uuid4()
    old_id    = uuid.uuid4()
    async with sf() as db:
        db.add(EmailOutboxModel(
            id=recent_id, notification_type="password_changed", recipient="r@x.com",
            subject="s", body_text="t", body_html=None, status="provider_accepted",
            attempt_count=1, available_at=utc_now(), created_at=utc_now(),
        ))
        db.add(EmailOutboxModel(
            id=old_id, notification_type="password_changed", recipient="o@x.com",
            subject="s", body_text="t", body_html=None, status="provider_accepted",
            attempt_count=1, available_at=utc_now(), created_at=utc_now() - timedelta(days=40),
        ))
        await db.commit()

    deleted = await _cleanup_email_outbox()  # default retention 30 days
    assert deleted == 1

    async with sf() as db:
        repo = EmailOutboxRepository(db)
        assert await repo.get_by_id(recent_id) is not None
        assert await repo.get_by_id(old_id) is None


# -- run() loop drains then stops -----------------------------------
async def test_run_loop_drains_batch_then_stops(sf):
    for i in range(3):
        await _enqueue(sf, NotificationType.PASSWORD_CHANGED, f"u{i}@x.com", _ctx())
    provider = FakeEmailProvider()
    stop = asyncio.Event()

    task = asyncio.create_task(email_delivery.run(
        sf, provider, "no-reply@wrapsec.com", "WrapSec",
        stop_event=stop, poll_seconds=1, batch=10, concurrency=3,
    ))
    # Give the loop time to claim and send the batch, then stop it.
    for _ in range(30):
        if len(provider.sent) >= 3:
            break
        await asyncio.sleep(0.1)
    stop.set()
    await asyncio.wait_for(task, timeout=5)

    assert len(provider.sent) == 3
