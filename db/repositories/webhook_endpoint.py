# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Repository for webhook endpoints (v1.3.0).

Sole consumer today is the outbound emitter, which calls
`find_active_for_event` once per BLOCK/SANITIZE decision to fan the
event out to every subscribed destination on the tenant. Query is
bounded by the composite index ix_webhook_endpoints_tenant_disabled.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import WebhookEndpointModel


class WebhookEndpointRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def find_active_for_event(
        self,
        *,
        tenant_id:  UUID,
        event_type: str,
    ) -> list[WebhookEndpointModel]:
        """
        Return every enabled webhook endpoint on `tenant_id` that
        subscribes to `event_type`.

        `event_types` is a JSON column with two documented meanings:
          * NULL  - wildcard: subscribe to every current and future event
                    without needing endpoint reconfiguration on release.
          * list  - explicit event names; only members match.

        Membership is filtered in Python rather than SQL because the
        JSON containment operator is dialect-specific (PostgreSQL @> vs
        SQLite json_each). Row count per tenant is small (typically
        under 20), so the DB does the tenant+disabled index seek and
        the Python filter is O(endpoints_on_tenant).
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
