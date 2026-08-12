# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
In-memory email provider for development and tests (v1.8.3).

Records every message in a list instead of contacting an SMTP server, so a
developer running WrapSec locally -- and the test suite -- cannot accidentally
send a real notification. Tests inspect `sent` to assert on delivered content,
and can arm `fail_next` to exercise the worker's transient/permanent retry
paths without a network stack.

This is the default provider whenever SMTP is not configured in a non-production
environment, satisfying the plan invariant: "Running WrapSec locally must not
accidentally send account/security emails to real addresses."
"""

from __future__ import annotations

import logging

from services.email.provider import (
    EmailProvider,
    OutgoingEmail,
    PermanentEmailError,
    TransientEmailError,
)

logger = logging.getLogger("wrapsec.email")


class FakeEmailProvider(EmailProvider):
    def __init__(self) -> None:
        self.sent: list[OutgoingEmail] = []
        # Optional one-shot failure injection for tests: set to "transient" or
        # "permanent" and the next send() raises the matching error, then clears.
        self.fail_next: str | None = None
        self._counter = 0

    async def send(self, message: OutgoingEmail) -> str:
        if self.fail_next is not None:
            mode = self.fail_next
            self.fail_next = None
            if mode == "transient":
                raise TransientEmailError("injected transient failure")
            raise PermanentEmailError("injected permanent failure")

        self._counter += 1
        message_id = message.message_id or f"<fake-{self._counter}@wrapsec.local>"
        self.sent.append(message)
        logger.info(
            "email sink accepted notification to=%s subject=%r id=%s",
            message.to_addr, message.subject, message_id,
        )
        return message_id
