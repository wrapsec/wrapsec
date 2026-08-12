# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Email delivery settings (v1.8.3).

System-level, admin-managed knobs for the email subsystem, stored as a single
JSON row in the shared settings table (the same store `audit_retention` uses):

  * notifications_enabled -- master on/off. When off, the trigger sites do not
    enqueue notifications at all.
  * max_attempts          -- how many send attempts before a message is failed.
  * retention_days        -- how long delivery records are kept.

Bounds and defaults are DERIVED FROM THE REAL retry schedule
(services.webhooks.retry_schedule), never hardcoded, so the setting can never
promise behavior the worker cannot honor:

  * The schedule defines a fixed set of backoff intervals; the total attempt
    ceiling is `MAX_ATTEMPTS = 1 + len(RETRY_SCHEDULE_SECONDS)`. Beyond that
    there is no defined backoff, so max_attempts is clamped to [1, MAX_ATTEMPTS].
  * The backoff intervals themselves are fixed policy (read-only in the UI); only
    the attempt ceiling and retention are tunable in V1.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import get_settings
from db.repositories.settings import SettingsRepository
from services.webhooks.retry_schedule import MAX_ATTEMPTS, RETRY_SCHEDULE_SECONDS

logger = logging.getLogger("wrapsec.email")

SETTINGS_KEY = "email_settings"

# Attempt ceiling is bounded by the real schedule: 1 (initial) + one per backoff
# interval. A configured max above this cannot be honored (no delay is defined),
# and a max below it simply gives up earlier.
MIN_MAX_ATTEMPTS = 1
MAX_MAX_ATTEMPTS = MAX_ATTEMPTS


@dataclass(frozen=True)
class EmailSettings:
    notifications_enabled: bool
    max_attempts:          int
    retention_days:        int


def _defaults() -> EmailSettings:
    return EmailSettings(
        notifications_enabled = True,
        max_attempts          = MAX_ATTEMPTS,
        retention_days        = get_settings().email_retention_days,
    )


def _coerce(raw: dict | None) -> EmailSettings:
    """Merge a stored dict over defaults, clamping to valid ranges. A malformed
    or partial record degrades to defaults for the missing/invalid fields rather
    than raising, so a bad row can never disable delivery outright."""
    d = _defaults()
    if not raw:
        return d

    enabled = raw.get("notifications_enabled", d.notifications_enabled)
    enabled = bool(enabled)

    try:
        max_attempts = int(raw.get("max_attempts", d.max_attempts))
    except (TypeError, ValueError):
        max_attempts = d.max_attempts
    max_attempts = max(MIN_MAX_ATTEMPTS, min(MAX_MAX_ATTEMPTS, max_attempts))

    try:
        retention_days = int(raw.get("retention_days", d.retention_days))
    except (TypeError, ValueError):
        retention_days = d.retention_days
    if retention_days < 1:
        retention_days = d.retention_days

    return EmailSettings(
        notifications_enabled = enabled,
        max_attempts          = max_attempts,
        retention_days        = retention_days,
    )


async def get_email_settings(db: AsyncSession) -> EmailSettings:
    """Effective settings: stored values merged over defaults."""
    raw = await SettingsRepository(db).get(SETTINGS_KEY)
    return _coerce(raw)


def validate_email_settings(
    *, notifications_enabled: bool, max_attempts: int, retention_days: int
) -> None:
    """Validate a candidate settings update. Raises ValueError on any violation
    (the API surfaces it as a 400). `notifications_enabled` is typed as bool at
    the request schema, so only the numeric ranges need checking here."""
    if not (MIN_MAX_ATTEMPTS <= max_attempts <= MAX_MAX_ATTEMPTS):
        raise ValueError(
            f"max_attempts must be between {MIN_MAX_ATTEMPTS} and {MAX_MAX_ATTEMPTS} "
            f"(the retry schedule defines {len(RETRY_SCHEDULE_SECONDS)} backoff intervals)"
        )
    if retention_days < 1:
        raise ValueError("retention_days must be >= 1")


async def set_email_settings(
    db: AsyncSession,
    *,
    notifications_enabled: bool,
    max_attempts:          int,
    retention_days:        int,
) -> EmailSettings:
    """Persist a validated settings update (flush only; caller commits)."""
    validate_email_settings(
        notifications_enabled = notifications_enabled,
        max_attempts          = max_attempts,
        retention_days        = retention_days,
    )
    await SettingsRepository(db).set(SETTINGS_KEY, {
        "notifications_enabled": notifications_enabled,
        "max_attempts":          max_attempts,
        "retention_days":        retention_days,
    })
    return EmailSettings(
        notifications_enabled = notifications_enabled,
        max_attempts          = max_attempts,
        retention_days        = retention_days,
    )
