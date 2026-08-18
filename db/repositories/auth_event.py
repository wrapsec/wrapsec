# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select

from db.models import AuthEventModel
from db.repositories.base import BaseRepository
from domain.enums import AuthEventAction, AuthFailureReason


class AuthEventRepository(BaseRepository):
    """
    Repository for auth_events table.

    Logging model: NON-BLOCKING. Must be called via BackgroundTasks or a
    separate DB session - never the request session. Must not delay login response.

    tenant_id and user_id are NULLABLE:
        Known user   -> set both from user record
        Unknown user -> both None (user not found, tenant cannot be resolved)
        Prefer None over incorrect attribution. Never use sentinel values.
    """

    async def insert(
        self,
        action:         AuthEventAction,
        success:        bool,
        tenant_id:      UUID | None            = None,
        user_id:        UUID | None            = None,
        failure_reason: AuthFailureReason | None = None,
        ip_address:     str  | None            = None,
        user_agent:     str  | None            = None,
    ) -> AuthEventModel:
        """
        Inserts a single auth event row.

        action must be a value from AuthEventAction enum.
        failure_reason must be a value from AuthFailureReason enum when success=False.
        failure_reason must be None when success=True.

        tenant_id/user_id rules:
            Login success          -> tenant_id=user.tenant_id, user_id=user.id
            Login fail (bad pwd)   -> tenant_id=user.tenant_id, user_id=user.id
            Login fail (inactive)  -> tenant_id=user.tenant_id, user_id=user.id
            Login fail (not found) -> tenant_id=None, user_id=None

        Uses flush() not commit() - caller owns the transaction and must commit.
        This repository never commits so it composes safely in multi-step operations.
        """
        event = AuthEventModel(
            tenant_id      = tenant_id,
            user_id        = user_id,
            action         = action.value,
            success        = success,
            failure_reason = failure_reason.value if failure_reason else None,
            ip_address     = ip_address,
            user_agent     = user_agent,
        )
        self.session.add(event)
        await self.session.flush()
        return event

    async def list_by_tenant(
        self,
        tenant_id:  UUID,
        user_id:    UUID | None = None,
        success:    bool | None = None,
        from_dt:    datetime | None = None,
        to_dt:      datetime | None = None,
        limit:      int = 50,
        offset:     int = 0,
    ) -> tuple[list[AuthEventModel], int]:
        """
        Lists auth events for a tenant with optional filters.
        Returns (events, total_count).

        Note: rows with tenant_id=None (unknown user attempts) are excluded
        from tenant-scoped queries - they have no tenant attribution.
        """
        query = select(AuthEventModel).where(
            AuthEventModel.tenant_id == tenant_id
        )

        if user_id:
            query = query.where(AuthEventModel.user_id == user_id)
        if success is not None:
            query = query.where(AuthEventModel.success == success)
        if from_dt:
            query = query.where(AuthEventModel.created_at >= from_dt)
        if to_dt:
            query = query.where(AuthEventModel.created_at <= to_dt)

        count_query = select(func.count()).select_from(query.subquery())
        total       = await self.session.scalar(count_query) or 0

        query  = query.order_by(AuthEventModel.created_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(query)
        events = list(result.scalars().all())

        return events, total

    async def count_failures_by_ip(
        self,
        ip_address: str,
        since:      datetime,
    ) -> int:
        """
        Counts failed login attempts from an IP address since a given time.
        Supports future brute-force detection without schema changes.
        Uses idx_auth_events_ip index.
        """
        result = await self.session.execute(
            select(func.count()).where(
                AuthEventModel.ip_address  == ip_address,
                AuthEventModel.success     == False,
                AuthEventModel.created_at  >= since,
            )
        )
        return result.scalar_one() or 0
