# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Repository for webhook endpoints (v1.3.0).

Consumers:

  * The outbound emitter calls `find_active_for_event` once per
    BLOCK/SANITIZE decision to fan the event out to every subscribed
    destination on the tenant. Query is bounded by the composite index
    ix_webhook_endpoints_tenant_disabled.

  * The concrete delivery handler calls `record_failure` after a
    failed HTTP attempt and `record_success` after a 2xx. Together
    those maintain the `first_failure_at` timer that the circuit
    breaker reads.

  * The circuit-breaker sweep worker calls `disable_stale` on its
    schedule to flip `disabled = True` on endpoints whose failure
    timer has exceeded the configured grace window.

Repository contract (per the CLAUDE.md invariant): methods flush()
so callers see DB-assigned state without committing. Callers are
responsible for commit().
"""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update
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

    async def record_failure(
        self,
        *,
        endpoint_id: UUID,
        now:         datetime | None = None,
    ) -> None:
        """
        Mark a delivery failure. Sets `first_failure_at` to `now` ONLY
        if the field is currently NULL -- subsequent failures MUST NOT
        reset the timer, otherwise a chronically flapping endpoint
        would never be disabled.

        Called by the concrete delivery handler on every non-2xx
        outcome. Idempotent under repeated calls between successes.

        `now` is a caller-supplied clock (default utcnow) so tests can
        pin a deterministic value without freezing wall time.
        """
        current = now or datetime.utcnow()
        stmt = (
            update(WebhookEndpointModel)
            .where(WebhookEndpointModel.id == endpoint_id)
            .where(WebhookEndpointModel.first_failure_at.is_(None))
            .values(first_failure_at=current, updated_at=current)
        )
        await self._db.execute(stmt)
        await self._db.flush()

    async def record_success(
        self,
        *,
        endpoint_id: UUID,
        now:         datetime | None = None,
    ) -> None:
        """
        Mark a delivery success. Clears `first_failure_at`, resetting
        the circuit-breaker timer so a later transient failure gets a
        fresh 120h grace window rather than counting from an outage
        the endpoint already recovered from.

        Called by the concrete delivery handler on every 2xx outcome.
        Cheap to call on every success (the UPDATE is a no-op when the
        field is already NULL).
        """
        current = now or datetime.utcnow()
        stmt = (
            update(WebhookEndpointModel)
            .where(WebhookEndpointModel.id == endpoint_id)
            .values(first_failure_at=None, updated_at=current)
        )
        await self._db.execute(stmt)
        await self._db.flush()

    async def disable_stale(
        self,
        *,
        threshold_hours: int,
        now:             datetime | None = None,
    ) -> list[UUID]:
        """
        Flip `disabled = True` on every endpoint whose failure timer
        has exceeded `threshold_hours`. Returns the list of IDs newly
        disabled so the caller can log them for operator triage.

        Filters:
          * `first_failure_at IS NOT NULL`  - healthy endpoints skip.
          * `disabled = False`              - already-disabled skip.
          * `first_failure_at <= cutoff`    - past the grace window.

        The cutoff comparison matches the boundary semantics in
        services.webhooks.circuit_breaker.should_disable (elapsed >=
        threshold disables).
        """
        if threshold_hours <= 0:
            raise ValueError(
                f"threshold_hours must be > 0, got {threshold_hours}"
            )

        current = now or datetime.utcnow()
        cutoff  = current - timedelta(hours=threshold_hours)

        select_stmt = (
            select(WebhookEndpointModel.id)
            .where(WebhookEndpointModel.first_failure_at.is_not(None))
            .where(WebhookEndpointModel.disabled.is_(False))
            .where(WebhookEndpointModel.first_failure_at <= cutoff)
        )
        stale_ids = list((await self._db.execute(select_stmt)).scalars().all())

        if not stale_ids:
            return []

        update_stmt = (
            update(WebhookEndpointModel)
            .where(WebhookEndpointModel.id.in_(stale_ids))
            .values(disabled=True, updated_at=current)
        )
        await self._db.execute(update_stmt)
        await self._db.flush()
        return stale_ids
