# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AdminEventModel
from db.repositories.base import BaseRepository
from domain.enums import AdminEventAction


class AdminEventRepository(BaseRepository):
    """
    Repository for admin_events table.

    Logging model: synchronous, post-commit, within the same request lifecycle.
    Best-effort - caller wraps insert() in try/except and continues on failure.

    All writes must use enum-controlled action values (AdminEventAction).
    dept_id rules:
        Tenant-scoped actions -> dept_id = None
        Dept-scoped actions   -> dept_id = target user's dept_id AFTER update
        For dept_changed      -> dept_id = new_dept_id
    """

    async def insert(
        self,
        tenant_id:      UUID,
        actor_user_id:  UUID,
        action:         AdminEventAction,
        dept_id:        UUID | None        = None,
        target_user_id: UUID | None        = None,
        metadata:       dict | None        = None,
        ip_address:     str  | None        = None,
        user_agent:     str  | None        = None,
    ) -> AdminEventModel:
        """
        Inserts a single admin event row.

        action must be a value from AdminEventAction enum - enforced by type hint.
        dept_id = None for tenant-scoped actions (settings changes, dept creation).
        dept_id = target user's post-update dept_id for user management actions.

        metadata key conventions (must be consistent per action type):
            role_changed  -> {"old_role": "...", "new_role": "..."}
            dept_changed  -> {"old_dept_id": "...", "new_dept_id": "..."}
            user_created  -> {"role": "...", "dept_id": "..."}

        Never include passwords, tokens, or secrets in metadata.
        """
        event = AdminEventModel(
            tenant_id      = tenant_id,
            dept_id        = dept_id,
            actor_user_id  = actor_user_id,
            target_user_id = target_user_id,
            action         = action.value,
            metadata_      = metadata,
            ip_address     = ip_address,
            user_agent     = user_agent,
        )
        self.session.add(event)
        await self.session.flush()
        return event

    async def list_by_tenant(
        self,
        tenant_id:  UUID,
        actor_id:   UUID | None = None,
        target_id:  UUID | None = None,
        action:     str  | None = None,
        dept_id:    UUID | None = None,
        from_dt:    datetime | None = None,
        to_dt:      datetime | None = None,
        limit:      int = 50,
        offset:     int = 0,
    ) -> tuple[list[AdminEventModel], int]:
        """
        Lists admin events for a tenant with optional filters.
        Returns (events, total_count).
        """
        query = select(AdminEventModel).where(
            AdminEventModel.tenant_id == tenant_id
        )

        if actor_id:
            query = query.where(AdminEventModel.actor_user_id == actor_id)
        if target_id:
            query = query.where(AdminEventModel.target_user_id == target_id)
        if action:
            query = query.where(AdminEventModel.action == action)
        if dept_id:
            query = query.where(AdminEventModel.dept_id == dept_id)
        if from_dt:
            query = query.where(AdminEventModel.created_at >= from_dt)
        if to_dt:
            query = query.where(AdminEventModel.created_at <= to_dt)

        count_query = select(func.count()).select_from(query.subquery())
        total       = await self.session.scalar(count_query) or 0

        query  = query.order_by(AdminEventModel.created_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(query)
        events = list(result.scalars().all())

        return events, total
