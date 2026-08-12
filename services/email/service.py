# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Email service -- the application boundary for enqueuing notifications (v1.8.3).

queue(db, ...) renders a notification and writes an outbox row on the caller's
session (flush only; the caller commits), so the row commits atomically with the
business change that triggered it. Rendering happens up front, so the outbox
stores final content and the delivery worker stays template-agnostic. A
rendering failure is logged and the notification skipped -- it never touches the
caller's transaction, so the business change still commits.

Trigger orchestration (locale resolution, context, and the best-effort
standalone path for triggers with no ambient transaction) lives in
services.email.notifications, which calls this boundary.
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
        department_id:     UUID | None = None,
        user_id:           UUID | None = None,
        trace_id:          str | None = None,
    ) -> EmailOutboxModel | None:
        """
        Render and enqueue a notification on the caller's session (flush only).
        Returns the outbox row, or None if rendering failed (skipped, logged).

        Rendering happens before any DB write, so a rendering failure leaves the
        caller's transaction untouched -- the business change still commits.

        Honors the master notifications on/off switch: when disabled, nothing is
        enqueued and None is returned.
        """
        from services.email.settings import get_email_settings

        if not (await get_email_settings(db)).notifications_enabled:
            logger.info(
                "email notifications disabled; skipping type=%s recipient=%s",
                notification_type.value, recipient,
            )
            return None

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
            department_id     = department_id,
            user_id           = user_id,
            trace_id          = trace_id,
        )
