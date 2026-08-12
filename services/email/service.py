# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Email service -- the application boundary for sending notifications (v1.8.3).

Two entry points, matching the two ways a notification is triggered:

  * queue(db, ...) enqueues an outbox row inside the CALLER'S transaction
    (flush only; the caller commits). Use this when the notification accompanies
    a database business change -- the outbox row then commits atomically with
    that change (password change, admin reset). If the business transaction
    rolls back, so does the email.

  * notify(...) is a best-effort standalone enqueue with its own session and
    commit. Use this when there is no ambient business transaction -- for
    example an account lockout, whose state lives in Redis. It never raises, so
    a notification failure cannot disrupt the triggering flow.

Both render the message up front (subject + bodies, localized) so the outbox
stores final content and the delivery worker stays template-agnostic. Rendering
failures degrade gracefully: they are logged and the notification is skipped,
never propagated into the caller's transaction.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from db.models import EmailOutboxModel
from db.repositories.email_outbox import EmailOutboxRepository
from domain.enums import NotificationType
from services.email.renderer import TemplateError, render

logger = logging.getLogger("wrapsec.email")


class EmailService:
    async def queue(
        self,
        db: AsyncSession,
        *,
        notification_type: NotificationType,
        recipient:         str,
        locale:            str | None,
        context:           dict[str, Any],
        tenant_id:         UUID | None = None,
        user_id:           UUID | None = None,
        trace_id:          str | None = None,
    ) -> EmailOutboxModel | None:
        """
        Render and enqueue a notification on the caller's session (flush only).
        Returns the outbox row, or None if rendering failed (skipped, logged).

        Rendering happens before any DB write, so a rendering failure leaves the
        caller's transaction untouched -- the business change still commits.
        """
        try:
            rendered = render(notification_type, locale, context)
        except TemplateError as exc:
            logger.error(
                "email render failed, skipping notification type=%s recipient=%s: %s",
                notification_type.value, recipient, exc,
            )
            return None

        repo = EmailOutboxRepository(db)
        return await repo.create(
            notification_type = notification_type.value,
            recipient         = recipient,
            subject           = rendered.subject,
            body_text         = rendered.text_body,
            body_html         = rendered.html_body,
            locale            = locale,
            tenant_id         = tenant_id,
            user_id           = user_id,
            trace_id          = trace_id,
        )

    async def notify(
        self,
        *,
        notification_type: NotificationType,
        recipient:         str,
        locale:            str | None,
        context:           dict[str, Any],
        tenant_id:         UUID | None = None,
        user_id:           UUID | None = None,
        trace_id:          str | None = None,
    ) -> None:
        """
        Best-effort standalone enqueue (own session + commit). Never raises.

        For triggers with no ambient database transaction. All exceptions --
        rendering, DB, commit -- are caught and logged so a notification failure
        cannot disrupt the flow that triggered it.
        """
        from db.session import AsyncSessionFactory

        try:
            async with AsyncSessionFactory() as db:
                row = await self.queue(
                    db,
                    notification_type = notification_type,
                    recipient         = recipient,
                    locale            = locale,
                    context           = context,
                    tenant_id         = tenant_id,
                    user_id           = user_id,
                    trace_id          = trace_id,
                )
                if row is not None:
                    await db.commit()
        except Exception as exc:  # noqa: BLE001 - best-effort, never disrupt caller
            logger.error(
                "email notify failed type=%s recipient=%s: %s",
                notification_type.value, recipient, exc,
            )
