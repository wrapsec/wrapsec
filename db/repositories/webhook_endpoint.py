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

  * The admin API (api/v1/endpoints/webhooks.py) calls the CRUD
    methods (create, get_by_id, list_by_tenant, update, delete),
    rotate_secret for signing-secret rotation with a receiver-side
    grace window, and reactivate for manual recovery after the
    circuit breaker has retired an endpoint.

Repository contract (per the CLAUDE.md invariant): methods flush()
so callers see DB-assigned state without committing. Callers are
responsible for commit().
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import delete as sa_delete
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import WebhookDeliveryAttemptModel, WebhookEndpointModel
from services.time import ensure_utc, parse_utc_iso, utc_now


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
        current = ensure_utc(now or utc_now())
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
        current = ensure_utc(now or utc_now())
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

        current = ensure_utc(now or utc_now())
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

    # ─── Admin CRUD ────────────────────────────────────────────────

    async def create(
        self,
        *,
        tenant_id:      UUID,
        url:            str,
        secret_enc:     str,
        description:    str | None = None,
        event_types:    list[str] | None = None,
        connector_type: str | None = None,
        config:         dict[str, Any] | None = None,
    ) -> WebhookEndpointModel:
        """
        Insert a new endpoint. `secret_enc` MUST already be envelope-
        encrypted by the caller via security.encryption.encrypt --
        this method never sees plaintext.

        `connector_type` NULL means a generic HMAC-signed webhook;
        a connector slug routes the endpoint through a SIEM connector
        and `config` carries that connector's per-endpoint options.
        connector_type is set once at create time and is not mutable
        through `update` -- changing it would reinterpret the stored
        secret material.
        """
        now = utc_now()
        ep  = WebhookEndpointModel(
            id             = uuid.uuid4(),
            tenant_id      = tenant_id,
            url            = url,
            description    = description,
            connector_type = connector_type,
            secret_enc     = secret_enc,
            old_secrets    = [],
            event_types    = event_types,
            config         = config,
            disabled       = False,
            created_at     = now,
        )
        self._db.add(ep)
        await self._db.flush()
        return ep

    async def get_by_id(self, endpoint_id: UUID) -> WebhookEndpointModel | None:
        """Fetch a single endpoint by id. Callers MUST also check
        that the returned row's tenant_id matches the caller's tenant
        before returning it -- this repo does not know the calling
        tenant."""
        return await self._db.get(WebhookEndpointModel, endpoint_id)

    async def list_by_tenant(
        self, tenant_id: UUID,
    ) -> list[WebhookEndpointModel]:
        """All endpoints on the tenant, disabled or not. Admin UI
        needs to see disabled endpoints to reactivate them."""
        stmt = (
            select(WebhookEndpointModel)
            .where(WebhookEndpointModel.tenant_id == tenant_id)
            .order_by(WebhookEndpointModel.created_at.desc())
        )
        return list((await self._db.execute(stmt)).scalars().all())

    async def update(
        self,
        *,
        endpoint_id: UUID,
        data:        dict[str, Any],
    ) -> WebhookEndpointModel | None:
        """
        Update mutable fields (url, description, event_types, config).

        `secret_enc`, `old_secrets`, `disabled`, `first_failure_at`,
        `tenant_id`, `created_at`, `connector_type` are intentionally
        NOT settable through this method -- each has a dedicated call
        path (rotate_secret, reactivate, record_failure, record_success,
        create) with the right invariants, and connector_type is
        immutable after create because it governs how secret_enc is
        interpreted. Passing them here is a caller bug.
        """
        allowed = {"url", "description", "event_types", "config"}
        clean   = {k: v for k, v in data.items() if k in allowed}
        if not clean:
            return await self.get_by_id(endpoint_id)

        clean["updated_at"] = utc_now()
        stmt = (
            update(WebhookEndpointModel)
            .where(WebhookEndpointModel.id == endpoint_id)
            .values(**clean)
        )
        await self._db.execute(stmt)
        await self._db.flush()
        return await self.get_by_id(endpoint_id)

    async def delete(self, endpoint_id: UUID) -> bool:
        """
        Hard delete. Returns True if a row was removed, False if the
        id did not exist (idempotent-friendly for the API layer).

        Webhook endpoints are per-tenant configuration, not audit
        history -- deleting is safe and expected. The audit trail of
        what was configured lives in admin_events, not in this table.
        """
        ep = await self._db.get(WebhookEndpointModel, endpoint_id)
        if ep is None:
            return False
        # Remove dependent delivery-attempt history first. The FK
        # webhook_delivery_attempts.endpoint_id has no ON DELETE CASCADE, so
        # hard-deleting an endpoint that has ever delivered raises a
        # ForeignKeyViolation (the row is still referenced). Those attempts are
        # per-endpoint operational history with nothing left to correlate to
        # once the endpoint is gone; the admin_events trail still records that
        # the endpoint was deleted. Same transaction, so it is all-or-nothing.
        await self._db.execute(
            sa_delete(WebhookDeliveryAttemptModel).where(
                WebhookDeliveryAttemptModel.endpoint_id == endpoint_id
            )
        )
        await self._db.delete(ep)
        await self._db.flush()
        return True

    async def rotate_secret(
        self,
        *,
        endpoint_id:    UUID,
        new_secret_enc: str,
        grace_hours:    int,
        now:            datetime | None = None,
    ) -> WebhookEndpointModel | None:
        """
        Rotate the signing secret.

        Moves the current `secret_enc` into `old_secrets` with an
        `expires_at` of now + grace_hours, then sets `secret_enc` to
        `new_secret_enc`. The webhook-signing library reads both the
        active secret and any non-expired old_secrets and signs each
        delivery with all of them, so a receiver that has not yet
        updated its verifier code keeps validating during the grace
        window.

        Any old_secrets whose expires_at is already in the past are
        pruned in the same call so the JSON array does not grow
        unbounded across many rotations.

        `new_secret_enc` MUST be pre-encrypted by the caller -- the
        repo never sees plaintext secret material.
        """
        if grace_hours <= 0:
            raise ValueError(f"grace_hours must be > 0, got {grace_hours}")

        current = ensure_utc(now or utc_now())
        ep      = await self._db.get(WebhookEndpointModel, endpoint_id)
        if ep is None:
            return None

        surviving = [
            entry for entry in (ep.old_secrets or [])
            if _entry_expires_at(entry) > current
        ]
        surviving.append({
            "ciphertext": ep.secret_enc,
            "expires_at": (current + timedelta(hours=grace_hours)).isoformat(),
        })

        stmt = (
            update(WebhookEndpointModel)
            .where(WebhookEndpointModel.id == endpoint_id)
            .values(
                secret_enc  = new_secret_enc,
                old_secrets = surviving,
                updated_at  = current,
            )
        )
        await self._db.execute(stmt)
        await self._db.flush()
        return await self.get_by_id(endpoint_id)

    async def pause(
        self,
        *,
        endpoint_id: UUID,
        now:         datetime | None = None,
    ) -> WebhookEndpointModel | None:
        """
        Manually pause delivery to an endpoint (admin action).

        Sets `disabled = True` without touching `first_failure_at`, so a paused
        healthy endpoint is distinguishable from one the circuit breaker retired
        (that one carries a failure timestamp). Config, secret, and delivery
        history are all preserved; resume via reactivate(). Idempotent.
        """
        current = ensure_utc(now or utc_now())
        stmt = (
            update(WebhookEndpointModel)
            .where(WebhookEndpointModel.id == endpoint_id)
            .values(disabled=True, updated_at=current)
        )
        await self._db.execute(stmt)
        await self._db.flush()
        return await self.get_by_id(endpoint_id)

    async def reactivate(
        self,
        *,
        endpoint_id: UUID,
        now:         datetime | None = None,
    ) -> WebhookEndpointModel | None:
        """
        Manual recovery after the circuit breaker retired an endpoint.

        Clears BOTH `disabled` and `first_failure_at` -- otherwise the
        endpoint would flip disabled again on the next sweep tick with
        no new failures having occurred, which is confusing for
        operators.

        Idempotent: safe to call on an already-active endpoint (no
        state changes, still returns the row).
        """
        current = ensure_utc(now or utc_now())
        stmt = (
            update(WebhookEndpointModel)
            .where(WebhookEndpointModel.id == endpoint_id)
            .values(
                disabled         = False,
                first_failure_at = None,
                updated_at       = current,
            )
        )
        await self._db.execute(stmt)
        await self._db.flush()
        return await self.get_by_id(endpoint_id)


def _entry_expires_at(entry: dict) -> datetime:
    """Parse the ISO datetime stored in an old_secrets entry. Missing
    or malformed values are treated as already expired so a corrupt
    row cannot indefinitely keep an old secret alive."""
    # Aware-UTC sentinel: expires_at columns are TIMESTAMPTZ and `current` in
    # the rotation path is aware, so a naive datetime.min would raise on the
    # comparison. parse_utc_iso normalizes any stored value (aware, offset, or
    # a legacy naive string) to aware UTC.
    raw = entry.get("expires_at")
    _expired = datetime.min.replace(tzinfo=timezone.utc)
    if not isinstance(raw, str):
        return _expired
    try:
        return parse_utc_iso(raw)
    except ValueError:
        return _expired
