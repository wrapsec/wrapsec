# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
SMTP email provider (v1.8.3).

The OSS transactional-email transport. Sends one message per call over a fresh
connection using aiosmtplib. A connection-per-send model is appropriate for the
low volume of security notifications and avoids the failure modes of a pooled
long-lived SMTP session (stale sockets, server-side idle timeouts).

The class's job beyond "send bytes" is to translate transport outcomes into the
provider failure contract (TransientEmailError vs PermanentEmailError) so the
worker can make a correct retry decision without any SMTP knowledge.

Security: credentials come only from settings and are never logged. Connection
errors are logged without the message body or headers.
"""

from __future__ import annotations

import asyncio
import logging

import aiosmtplib

from services.email.provider import (
    EmailProvider,
    OutgoingEmail,
    PermanentEmailError,
    TransientEmailError,
    build_mime,
)

logger = logging.getLogger("wrapsec.email")


class SMTPProvider(EmailProvider):
    def __init__(
        self,
        *,
        host:      str,
        port:      int,
        username:  str | None,
        password:  str | None,
        use_tls:   bool,
        start_tls: bool,
        timeout:   int,
    ) -> None:
        # use_tls and start_tls are mutually exclusive (implicit TLS vs STARTTLS);
        # settings.validate_email_config enforces this, but normalize defensively
        # so a direct constructor call cannot hand aiosmtplib an invalid combo.
        if use_tls and start_tls:
            raise ValueError("use_tls and start_tls are mutually exclusive")
        self._host      = host
        self._port      = port
        self._username  = username or None
        self._password  = password or None
        self._use_tls   = use_tls
        self._start_tls = start_tls
        self._timeout   = timeout

    async def send(self, message: OutgoingEmail) -> str:
        mime       = build_mime(message)
        message_id = str(mime["Message-ID"])

        try:
            errors, _response = await aiosmtplib.send(
                mime,
                sender     = message.from_addr,
                recipients = [message.to_addr],
                hostname   = self._host,
                port       = self._port,
                username   = self._username,
                password   = self._password,
                use_tls    = self._use_tls,
                start_tls  = self._start_tls,
                timeout    = self._timeout,
            )
        except aiosmtplib.SMTPRecipientsRefused as exc:
            # Every recipient was rejected. For a single-recipient notification
            # this is a bad/undeliverable address -- permanent.
            raise PermanentEmailError(f"recipient refused: {_safe_smtp(exc)}") from exc
        except aiosmtplib.SMTPSenderRefused as exc:
            raise _classify_by_code(getattr(exc, "code", None), f"sender refused: {_safe_smtp(exc)}") from exc
        except aiosmtplib.SMTPAuthenticationError as exc:
            # Bad credentials are a configuration problem; retrying the same
            # message will not help until an operator fixes settings.
            raise PermanentEmailError(f"authentication failed: {_safe_smtp(exc)}") from exc
        except aiosmtplib.SMTPResponseException as exc:
            # Generic server response error carrying an SMTP status code.
            raise _classify_by_code(getattr(exc, "code", None), f"smtp error: {_safe_smtp(exc)}") from exc
        except (
            aiosmtplib.SMTPConnectError,
            aiosmtplib.SMTPServerDisconnected,
            aiosmtplib.SMTPTimeoutError,
            asyncio.TimeoutError,
            ConnectionError,
            OSError,
        ) as exc:
            # Network/connection-level problems are transient by nature.
            raise TransientEmailError(f"connection error: {type(exc).__name__}: {exc}") from exc
        except aiosmtplib.SMTPException as exc:
            # Unknown SMTP-layer error: prefer a bounded retry over silently
            # dropping the message. MAX_ATTEMPTS caps the blast radius.
            raise TransientEmailError(f"smtp error: {type(exc).__name__}: {_safe_smtp(exc)}") from exc

        if errors:
            # Partial refusal (some recipients accepted, some not). We send to a
            # single recipient, so any entry means that recipient was refused.
            raise PermanentEmailError(f"recipient refused: {sorted(errors.keys())}")

        return message_id


def _classify_by_code(code: int | None, detail: str) -> TransientEmailError | PermanentEmailError:
    """
    SMTP reply codes: 4xx are transient (try again later), 5xx are permanent
    (do not retry). An unknown/missing code is treated as transient so a
    genuinely temporary condition is not misclassified as a hard failure.
    """
    if code is not None and 500 <= code < 600:
        return PermanentEmailError(detail)
    return TransientEmailError(detail)


def _safe_smtp(exc: Exception) -> str:
    """Compact, credential-free rendering of an SMTP exception for logs/errors."""
    code    = getattr(exc, "code", None)
    message = getattr(exc, "message", None)
    if code is not None:
        return f"{code} {message if message is not None else exc}"
    return str(exc)
