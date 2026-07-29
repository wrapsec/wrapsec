# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Repository for webhook_endpoints. Reads only in v1.3.0; CRUD lands with the
admin endpoints commit (#8). The emitter path uses find_active_for_event on
every BLOCK/SANITIZE decision, so it MUST stay a single indexed lookup --
the ix_webhook_endpoints_tenant_disabled composite index covers the WHERE
clause below.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import WebhookEndpointModel


class WebhookEndpointRepository:
    """Reads for the delivery emitter. Write path lives in commit #8."""

    def __init__(self, db: AsyncSession):
        self._db = db

    async def find_active_for_event(
        self,
        tenant_id:  UUID,
        event_type: str,
    ) -> list[WebhookEndpointModel]:
        """
        Return every enabled endpoint for this tenant that subscribes to
        `event_type`. An endpoint with event_types=None subscribes to
        everything; an endpoint with a list subscribes only if the event
        name appears in it.

        Filter is applied in Python (not SQL) because event_types is a JSON
        column and the matching predicate differs between JSONB (postgres)
        and JSON (sqlite). Endpoints-per-tenant is O(few) so the fanout is
        cheap; the index-covered WHERE keeps this a single row-count-bounded
        seek regardless of tenant count.
        """
        stmt = (
            select(WebhookEndpointModel)
            .where(WebhookEndpointModel.tenant_id == tenant_id)
            .where(WebhookEndpointModel.disabled.is_(False))
        )
        rows = (await self._db.execute(stmt)).scalars().all()

        return [
            ep for ep in rows
            if ep.event_types is None or event_type in ep.event_types
        ]
