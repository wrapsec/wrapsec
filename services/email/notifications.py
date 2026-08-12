# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Security-notification triggers (v1.8.3).

One well-named function per notification, so trigger sites stay a single line
and all the orchestration (locale resolution, context, session handling) lives
here. Each recipient is the account's stored email; nothing here trusts a
client-supplied address.

Transaction model:

  * notify_password_changed / notify_admin_password_reset enqueue on the
    CALLER'S session (flush only) so the outbox row commits atomically with the
    password change. This does not couple the business action to email
    *delivery*: enqueue is a local INSERT that succeeds whenever the business
    UPDATE can, and SMTP being down never affects it (delivery is asynchronous).
    A rendering failure is swallowed inside EmailService.queue and the business
    change still commits.

  * notify_account_locked has no ambient business transaction (lockout state
    lives in Redis), so it opens its own session and commits, fully best-effort:
    any failure is logged and never propagates into the login flow.
"""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from db.models import UserModel
from db.repositories.tenant import TenantRepository
from domain.enums import NotificationType
from services.email.service import EmailService
from services.localization import resolve_locale
from services.time import to_iso_z, utc_now

logger = logging.getLogger("wrapsec.email")


async def _resolve_user_locale(db: AsyncSession, user: UserModel) -> str:
    """Effective locale for a user: User -> Tenant -> System -> English."""
    tenant_locale = None
    if user.tenant_id is not None:
        tenant = await TenantRepository(db).get_by_id(user.tenant_id)
        tenant_locale = tenant.locale if tenant else None
    return resolve_locale(user.locale, tenant_locale)


def _event_time() -> str:
    return to_iso_z(utc_now())


async def notify_password_changed(
    db: AsyncSession, user: UserModel, *, trace_id: str | None = None
) -> None:
    """Enqueue a password-changed confirmation on the caller's session."""
    locale = await _resolve_user_locale(db, user)
    await EmailService().queue(
        db,
        notification_type = NotificationType.PASSWORD_CHANGED,
        recipient         = user.email,
        locale            = locale,
        context           = {"display_name": user.email, "event_time": _event_time()},
        tenant_id         = user.tenant_id,
        department_id     = user.dept_id,
        user_id           = user.id,
        trace_id          = trace_id,
    )


async def notify_admin_password_reset(
    db: AsyncSession, user: UserModel, *, trace_id: str | None = None
) -> None:
    """Enqueue an admin-password-reset notice on the caller's session."""
    locale = await _resolve_user_locale(db, user)
    await EmailService().queue(
        db,
        notification_type = NotificationType.PASSWORD_RESET_BY_ADMIN,
        recipient         = user.email,
        locale            = locale,
        context           = {"display_name": user.email, "event_time": _event_time()},
        tenant_id         = user.tenant_id,
        department_id     = user.dept_id,
        user_id           = user.id,
        trace_id          = trace_id,
    )


async def notify_account_locked(
    user: UserModel, *, lockout_seconds: int, trace_id: str | None = None
) -> None:
    """
    Best-effort standalone enqueue of an account-locked notification. Opens its
    own session and commits; never raises, so a notification failure cannot
    disrupt the login flow that triggered it.
    """
    from db.session import AsyncSessionFactory

    lockout_minutes = max(1, round(lockout_seconds / 60))
    try:
        async with AsyncSessionFactory() as db:
            locale = await _resolve_user_locale(db, user)
            row = await EmailService().queue(
                db,
                notification_type = NotificationType.ACCOUNT_LOCKED,
                recipient         = user.email,
                locale            = locale,
                context           = {
                    "display_name":    user.email,
                    "event_time":      _event_time(),
                    "lockout_minutes": str(lockout_minutes),
                },
                tenant_id     = user.tenant_id,
                department_id = user.dept_id,
                user_id       = user.id,
                trace_id      = trace_id,
            )
            if row is not None:
                await db.commit()
    except Exception as exc:  # noqa: BLE001 - best-effort, never disrupt login
        logger.error("account_locked notification failed user_id=%s: %s", user.id, exc)
