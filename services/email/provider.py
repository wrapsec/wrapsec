# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Email provider boundary (v1.8.3).

Defines the small, transport-agnostic contract the outbox worker uses to send a
message, plus the shared MIME builder. Concrete transports live alongside:

  * smtp_provider.SMTPProvider  -- the OSS SMTP transport
  * fake_provider.FakeEmailProvider -- an in-memory sink for dev and tests

The interface is intentionally minimal so a future transactional-provider
capability can be added without changing application-level notification code.

Failure contract (this is how the worker decides retry vs. give-up):

  * send() returns a provider message id string on success.
  * send() raises TransientEmailError for a failure that may succeed on retry
    (connection drop, timeout, 4xx SMTP, provider outage).
  * send() raises PermanentEmailError for a failure that will not succeed on
    retry (malformed recipient, 5xx rejection, auth/config problem).

Keeping the retry/permanent decision inside the provider (which is the only
layer that understands transport-specific error codes) keeps the worker
transport-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import make_msgid


class EmailProviderError(Exception):
    """Base class for provider send failures."""


class TransientEmailError(EmailProviderError):
    """A retryable failure. The worker reschedules per the retry schedule."""


class PermanentEmailError(EmailProviderError):
    """A non-retryable failure. The worker marks the row failed immediately."""


@dataclass(frozen=True)
class OutgoingEmail:
    """
    A fully-rendered, ready-to-send message.

    Rendering (subject/body localization) happens upstream at enqueue time, so a
    provider receives only final content and never needs locale or template
    knowledge. `message_id` is the RFC 5322 Message-ID; when omitted the MIME
    builder generates one. It is persisted as the provider message id so an
    operator can correlate an outbox row with mail-server logs.
    """
    to_addr:    str
    subject:    str
    text_body:  str
    html_body:  str | None
    from_addr:  str
    from_name:  str = "WrapSec"
    message_id: str | None = None
    headers:    dict[str, str] = field(default_factory=dict)


def build_mime(message: OutgoingEmail) -> EmailMessage:
    """
    Build a MIME message from an OutgoingEmail.

    Produces a plain-text message, or a multipart/alternative (text + HTML) when
    an HTML body is present, so every client -- including text-only ones --
    renders a readable message. A Message-ID is set (generated if not supplied)
    and echoed back by providers as the provider message id.

    Header values are set through the stdlib email API, which folds and encodes
    them; callers must still ensure address/subject content is trusted or
    escaped upstream (it is: notification content is template-rendered, not
    attacker-controlled free text).
    """
    msg = EmailMessage()
    # from_name is a display label; Address() quotes/encodes it safely.
    try:
        local, _, domain = message.from_addr.partition("@")
        msg["From"] = Address(display_name=message.from_name, username=local, domain=domain)
    except (ValueError, IndexError):
        # Fall back to the bare address if it is not in local@domain shape;
        # the provider will surface a permanent error if it is truly invalid.
        msg["From"] = message.from_addr
    msg["To"]      = message.to_addr
    msg["Subject"] = message.subject

    message_id = message.message_id or make_msgid()
    msg["Message-ID"] = message_id

    # Additional headers (e.g. Auto-Submitted) are applied verbatim. These are
    # set by trusted callers only, never from request input.
    for key, value in message.headers.items():
        if key.lower() in ("from", "to", "subject", "message-id"):
            continue  # never let extra headers override the core ones
        msg[key] = value

    msg.set_content(message.text_body)
    if message.html_body:
        msg.add_alternative(message.html_body, subtype="html")
    return msg


class EmailProvider(ABC):
    """Transport contract. See module docstring for the failure semantics."""

    @abstractmethod
    async def send(self, message: OutgoingEmail) -> str:
        """
        Deliver `message`. Return a provider message id on success; raise
        TransientEmailError or PermanentEmailError on failure.
        """
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release any held resources. Default is a no-op."""
        return
