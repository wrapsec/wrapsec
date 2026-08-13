# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Repository for webhook_delivery_attempts (v1.3.0).

Append-only per-attempt log. The delivery handler calls `record` once per
delivery attempt (first try and every retry) so the dashboard delivery-log
UI (v1.3.1) and operator triage have a truthful history of what was
attempted, the receiver's status, and how long it took.

Per the CLAUDE.md invariant this repo flushes; the delivery handler owns
the session and commits.

Status vocabulary (String(20)):
  * success  - receiver returned 2xx.
  * failed   - attempt failed and a retry is scheduled (next_attempt_at set).
  * dead     - attempt failed and retries are exhausted / permanent; the
               message went to the dead-letter stream.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from db.models import WebhookDeliveryAttemptModel
from services.time import utc_now

STATUS_SUCCESS = "success"
STATUS_FAILED  = "failed"
STATUS_DEAD    = "dead"


class WebhookDeliveryAttemptRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def record(
        self,
        *,
        endpoint_id:      UUID,
        tenant_id:        UUID,
        msg_id:           str,
        url:              str,
        event_type:       str,
        attempt_number:   int,
        status:           str,
        http_status_code: int | None = None,
        response_snippet: str | None = None,
        duration_ms:      int | None = None,
        error_message:    str | None = None,
        next_attempt_at:  datetime | None = None,
        now:              datetime | None = None,
    ) -> WebhookDeliveryAttemptModel:
        """
        Insert one delivery-attempt row. `created_at` is part of the
        composite PK (postgres RANGE partitioning key) and `ended_at`
        marks when this attempt finished; both default to `now`.
        """
        current = now or utc_now()
        row = WebhookDeliveryAttemptModel(
            id                      = uuid.uuid4(),
            created_at              = current,
            endpoint_id             = endpoint_id,
            tenant_id               = tenant_id,
            msg_id                  = msg_id,
            url                     = url,
            event_type              = event_type,
            attempt_number          = attempt_number,
            status                  = status,
            http_status_code        = http_status_code,
            response_body_truncated = response_snippet,
            response_duration_ms    = duration_ms,
            error_message           = error_message,
            next_attempt_at         = next_attempt_at,
            ended_at                = current,
        )
        self._db.add(row)
        await self._db.flush()
        return row
