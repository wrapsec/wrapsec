# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for EmailService.queue (v1.8.3, Phase C).

Uses a fake session (create() assigns its own id, so no database is needed).
Worker claim/mark paths need SELECT ... FOR UPDATE SKIP LOCKED and are covered
by the integration suite against real PostgreSQL.
"""

from __future__ import annotations

import uuid

import pytest

from domain.enums import IMPLEMENTED_NOTIFICATIONS, EmailStatus, NotificationType
from services.email.service import EmailService


class _NoRow:
    def scalar_one_or_none(self):
        return None


class FakeSession:
    """Minimal AsyncSession stand-in: records added rows, flush is a no-op, and
    any query returns no row -- so the email-settings lookup falls back to
    defaults (notifications enabled)."""

    def __init__(self) -> None:
        self.added: list = []

    def add(self, obj) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None

    async def execute(self, *args, **kwargs) -> _NoRow:
        return _NoRow()


async def test_queue_renders_and_enqueues_row():
    db  = FakeSession()
    tid = uuid.uuid4()
    uid = uuid.uuid4()
    row = await EmailService().queue(
        db,
        notification_type=NotificationType.PASSWORD_CHANGED,
        recipient="user@example.com",
        locale="en",
        context={"display_name": "user@example.com", "event_time": "2026-08-12T10:00:00Z"},
        tenant_id=tid,
        user_id=uid,
        trace_id="trace-123",
    )
    assert row is not None
    assert db.added == [row]
    assert row.status == EmailStatus.QUEUED.value
    assert row.attempt_count == 0
    assert row.notification_type == "password.changed"
    assert row.recipient == "user@example.com"
    assert row.tenant_id == tid
    assert row.user_id == uid
    assert row.trace_id == "trace-123"
    assert "password was changed" in row.subject
    assert row.body_text.strip()
    assert row.body_html and row.body_html.strip().startswith("<")
    assert row.available_at is not None and row.created_at is not None


async def test_queue_localizes_subject_by_locale():
    db = FakeSession()
    row = await EmailService().queue(
        db,
        notification_type=NotificationType.PASSWORD_CHANGED,
        recipient="user@example.com",
        locale="de",
        context={"display_name": "x", "event_time": "t"},
    )
    assert "geändert" in row.subject


async def test_queue_degrades_gracefully_on_render_error():
    db = FakeSession()
    # account_locked requires lockout_minutes; omitting it makes render fail.
    row = await EmailService().queue(
        db,
        notification_type=NotificationType.ACCOUNT_LOCKED,
        recipient="user@example.com",
        locale="en",
        context={"display_name": "x", "event_time": "t"},
    )
    assert row is None
    assert db.added == []  # nothing written to the caller's transaction


@pytest.mark.parametrize("nt", list(IMPLEMENTED_NOTIFICATIONS))
async def test_queue_supports_every_implemented_type(nt):
    from services.email.renderer import REQUIRED_CONTEXT

    db  = FakeSession()
    ctx = {k: "v" for k in REQUIRED_CONTEXT[nt]}
    row = await EmailService().queue(
        db,
        notification_type=nt,
        recipient="user@example.com",
        locale="en",
        context=ctx,
    )
    assert row is not None
    assert row.notification_type == nt.value


async def test_queue_skips_reserved_type():
    # A registered-but-not-implemented type is skipped (returns None, nothing
    # written), distinct from the master-switch skip.
    reserved = next(iter(set(NotificationType) - IMPLEMENTED_NOTIFICATIONS))
    db = FakeSession()
    row = await EmailService().queue(
        db,
        notification_type=reserved,
        recipient="user@example.com",
        locale="en",
        context={"display_name": "x", "event_time": "t"},
    )
    assert row is None
    assert db.added == []
