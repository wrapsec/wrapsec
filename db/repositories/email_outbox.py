# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Repository for the transactional email outbox (v1.8.3).

Consumers:

  * EmailService.queue() calls create() inside the caller's business
    transaction, so the outbox row commits atomically with the business change.
  * The delivery worker calls claim_batch() to atomically take a batch of due
    rows (SELECT ... FOR UPDATE SKIP LOCKED so concurrent workers never claim
    the same row), then mark_accepted() / reschedule() / mark_failed() per send
    outcome.
  * The admin/auditor API lists rows via list_by_tenant() / get_by_id() for the
    tenant-scoped email audit view.

Repository contract (per the CLAUDE.md invariant): methods flush() so callers
see DB-assigned state without committing. Callers own commit(). The worker
commits immediately after claim_batch() to persist the 'sending' transition and
release the row locks before it starts sending.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import EmailOutboxModel
from domain.enums import EmailStatus
from services.time import ensure_utc, utc_now


class EmailOutboxRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def create(
        self,
        *,
        notification_type: str,
        recipient:         str,
        subject:           str,
        body_text:         str,
        body_html:         str | None,
        locale:            str | None = None,
        tenant_id:         UUID | None = None,
        department_id:     UUID | None = None,
        user_id:           UUID | None = None,
        trace_id:          str | None = None,
        now:               datetime | None = None,
    ) -> EmailOutboxModel:
        """
        Insert a queued outbox row. Content is already rendered by the caller.
        Does not commit -- the row becomes durable when the caller commits its
        business transaction.
        """
        import uuid

        current = ensure_utc(now or utc_now())
        row = EmailOutboxModel(
            id                = uuid.uuid4(),
            tenant_id         = tenant_id,
            department_id     = department_id,
            user_id           = user_id,
            notification_type = notification_type,
            recipient         = recipient,
            locale            = locale,
            subject           = subject,
            body_text         = body_text,
            body_html         = body_html,
            status            = EmailStatus.QUEUED.value,
            attempt_count     = 0,
            available_at      = current,
            created_at        = current,
            trace_id          = trace_id,
        )
        self._db.add(row)
        await self._db.flush()
        return row

    async def claim_batch(
        self,
        *,
        limit: int,
        now:   datetime | None = None,
    ) -> list[EmailOutboxModel]:
        """
        Atomically claim up to `limit` due rows: status 'queued' and
        available_at <= now, oldest first. Locked rows already held by another
        worker are skipped (FOR UPDATE SKIP LOCKED), so two workers never
        process the same message. Claimed rows are moved to 'sending'.

        The caller MUST commit after this returns to persist the transition and
        release the locks before sending.
        """
        current = ensure_utc(now or utc_now())
        stmt = (
            select(EmailOutboxModel)
            .where(EmailOutboxModel.status == EmailStatus.QUEUED.value)
            .where(EmailOutboxModel.available_at <= current)
            .order_by(EmailOutboxModel.available_at.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        rows = list((await self._db.execute(stmt)).scalars().all())
        for row in rows:
            row.status     = EmailStatus.SENDING.value
            row.sending_at = current
            row.updated_at = current
        await self._db.flush()
        return rows

    async def mark_accepted(
        self,
        *,
        row_id:              UUID,
        attempt_count:       int,
        provider_message_id: str | None,
        now:                 datetime | None = None,
    ) -> None:
        """Terminal success: the provider accepted the message for relay."""
        current = ensure_utc(now or utc_now())
        row = await self._db.get(EmailOutboxModel, row_id)
        if row is None:
            return
        row.status              = EmailStatus.PROVIDER_ACCEPTED.value
        row.attempt_count       = attempt_count
        row.provider_message_id = provider_message_id
        row.sent_at             = current
        row.updated_at          = current
        await self._db.flush()

    async def mark_failed(
        self,
        *,
        row_id:        UUID,
        attempt_count: int,
        error:         str,
        now:           datetime | None = None,
    ) -> None:
        """Terminal failure: non-retryable, or retries exhausted."""
        current = ensure_utc(now or utc_now())
        row = await self._db.get(EmailOutboxModel, row_id)
        if row is None:
            return
        row.status        = EmailStatus.FAILED.value
        row.attempt_count = attempt_count
        row.last_error    = _truncate(error)
        row.updated_at    = current
        await self._db.flush()

    async def reschedule(
        self,
        *,
        row_id:        UUID,
        attempt_count: int,
        available_at:  datetime,
        error:         str,
        now:           datetime | None = None,
    ) -> None:
        """
        Transient failure: return the row to 'queued' with a future
        available_at so the shared retry schedule spaces the next attempt.
        """
        current = ensure_utc(now or utc_now())
        row = await self._db.get(EmailOutboxModel, row_id)
        if row is None:
            return
        row.status        = EmailStatus.QUEUED.value
        row.attempt_count = attempt_count
        row.available_at  = ensure_utc(available_at)
        row.last_error    = _truncate(error)
        row.updated_at    = current
        await self._db.flush()

    # -- audit / admin listing -------------------------------------------------

    async def get_by_id(self, row_id: UUID) -> EmailOutboxModel | None:
        """Fetch one row. Callers MUST verify tenant ownership before returning
        it -- this repo does not know the calling tenant."""
        return await self._db.get(EmailOutboxModel, row_id)

    def _filtered(
        self,
        stmt,
        *,
        tenant_id:         UUID,
        status:            str | None,
        notification_type: str | None,
        department_id:     UUID | None,
        recipient:         str | None,
        created_from:      datetime | None,
        created_to:        datetime | None,
    ):
        """Apply the shared delivery-audit filters to a select. Always
        tenant-scoped; recipient is a case-insensitive substring match."""
        stmt = stmt.where(EmailOutboxModel.tenant_id == tenant_id)
        if status is not None:
            stmt = stmt.where(EmailOutboxModel.status == status)
        if notification_type is not None:
            stmt = stmt.where(EmailOutboxModel.notification_type == notification_type)
        if department_id is not None:
            stmt = stmt.where(EmailOutboxModel.department_id == department_id)
        if recipient:
            stmt = stmt.where(EmailOutboxModel.recipient.ilike(f"%{recipient}%"))
        if created_from is not None:
            stmt = stmt.where(EmailOutboxModel.created_at >= ensure_utc(created_from))
        if created_to is not None:
            stmt = stmt.where(EmailOutboxModel.created_at <= ensure_utc(created_to))
        return stmt

    async def list_by_tenant(
        self,
        *,
        tenant_id:         UUID,
        limit:             int = 50,
        offset:            int = 0,
        status:            str | None = None,
        notification_type: str | None = None,
        department_id:     UUID | None = None,
        recipient:         str | None = None,
        created_from:      datetime | None = None,
        created_to:        datetime | None = None,
    ) -> list[EmailOutboxModel]:
        """Tenant-scoped listing, newest first, for the delivery audit view."""
        stmt = self._filtered(
            select(EmailOutboxModel),
            tenant_id=tenant_id, status=status, notification_type=notification_type,
            department_id=department_id, recipient=recipient,
            created_from=created_from, created_to=created_to,
        )
        stmt = stmt.order_by(EmailOutboxModel.created_at.desc()).limit(limit).offset(offset)
        return list((await self._db.execute(stmt)).scalars().all())

    async def count_by_status(
        self,
        *,
        tenant_id:         UUID,
        notification_type: str | None = None,
        department_id:     UUID | None = None,
        recipient:         str | None = None,
        created_from:      datetime | None = None,
        created_to:        datetime | None = None,
    ) -> dict[str, int]:
        """Per-status counts for the summary row, with the same filters as the
        listing (minus status). Every EmailStatus is present, zero-filled."""
        from domain.enums import EmailStatus

        stmt = self._filtered(
            select(EmailOutboxModel.status, func.count()).select_from(EmailOutboxModel),
            tenant_id=tenant_id, status=None, notification_type=notification_type,
            department_id=department_id, recipient=recipient,
            created_from=created_from, created_to=created_to,
        ).group_by(EmailOutboxModel.status)
        rows = (await self._db.execute(stmt)).all()
        counts = {s.value: 0 for s in EmailStatus}
        for status_value, count in rows:
            counts[status_value] = count
        return counts


# Cap on the persisted error string so a verbose SMTP transcript cannot bloat
# the row. The full error is always available in the worker logs.
_MAX_ERROR_CHARS = 500


def _truncate(text: str) -> str:
    text = (text or "").strip()
    return text if len(text) <= _MAX_ERROR_CHARS else text[: _MAX_ERROR_CHARS - 3] + "..."
