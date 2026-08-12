# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Email provider selection (v1.8.3).

Central place that decides which transport (if any) is active for the current
configuration, so the lifespan worker and any operational check agree on one
answer.

Rules:
  * SMTP configured (smtp_host set)         -> SMTPProvider (real delivery).
  * SMTP unset, non-production environment  -> FakeEmailProvider (local sink).
  * SMTP unset, production                  -> None (email disabled).

Returning None is a first-class outcome, not an error: email is optional
infrastructure. The delivery worker does not start when the provider is None,
and business actions that would send a notification still complete.
"""

from __future__ import annotations

import logging

from config.settings import Settings
from services.email.provider import EmailProvider

logger = logging.getLogger("wrapsec.email")


def get_email_provider(settings: Settings) -> EmailProvider | None:
    """Construct the active provider, or None when email is disabled."""
    if settings.smtp_host:
        from services.email.smtp_provider import SMTPProvider

        return SMTPProvider(
            host      = settings.smtp_host,
            port      = settings.smtp_port,
            username  = settings.smtp_username,
            password  = settings.smtp_password,
            use_tls   = settings.smtp_use_tls,
            start_tls = settings.smtp_start_tls,
            timeout   = settings.smtp_timeout_seconds,
        )

    env = (settings.environment or "").strip().lower()
    if env == "production":
        logger.warning(
            "email disabled: SMTP_HOST is not configured in production; "
            "security notifications will be queued but not delivered"
        )
        return None

    # Development / staging convenience: a local sink so nothing leaves the host
    # and developers can still see notifications being produced.
    from services.email.fake_provider import FakeEmailProvider

    logger.info(
        "email using in-memory sink: SMTP_HOST not configured (environment=%s)", env or "unset"
    )
    return FakeEmailProvider()


def email_from_address(settings: Settings) -> tuple[str, str]:
    """
    Resolve the From: (address, display name) for outgoing mail.

    When SMTP is configured, smtp_from is required (settings validation
    enforces it). The fallback address is only reachable for the non-production
    in-memory sink, where the value is never actually sent anywhere.
    """
    return (settings.smtp_from or "no-reply@wrapsec.local", settings.smtp_from_name)
