# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import DepartmentModel, UserModel
from db.repositories.base import BaseRepository


class UserRepository(BaseRepository):

    async def get_by_email(self, email: str) -> UserModel | None:
        """
        Case-insensitive email lookup using LOWER() to match ux_users_email_lower index.

        CRITICAL: ALWAYS use func.lower() in the WHERE clause.
        NEVER use WHERE email = :email — that query does NOT use the index
        and breaks case-insensitive uniqueness guarantees.

        email parameter must already be normalized via normalize_email()
        before calling this method.
        """
        result = await self.session.execute(
            select(UserModel).where(func.lower(UserModel.email) == email)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: UUID) -> UserModel | None:
        result = await self.session.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        return result.scalar_one_or_none()

    async def create(self, data: dict) -> UserModel:
        """
        Creates a new user.

        Required keys: tenant_id (UUID), email (pre-normalized), password_hash, role
        Optional keys: dept_id (UUID), force_password_change (bool)

        Validations performed before insert:
        1. role must be in (ADMIN, DEVELOPER, VIEWER) — raises ValueError otherwise
        2. dept_id required if role != ADMIN — raises ValueError if missing
        3. dept_id tenant integrity check: if dept_id is provided, verifies that
           the department belongs to the same tenant as the user.
           Raises ValueError if dept does not belong to tenant.
           Prevents cross-tenant data linkage via bad input.
        """
        role    = data.get("role", "DEVELOPER")
        dept_id = data.get("dept_id")

        if role not in ("ADMIN", "DEVELOPER", "VIEWER"):
            raise ValueError(f"Invalid role '{role}'. Must be ADMIN, DEVELOPER, or VIEWER.")

        if role != "ADMIN" and not dept_id:
            raise ValueError(f"dept_id is required for role '{role}'.")

        if dept_id:
            await self._verify_dept_belongs_to_tenant(
                dept_id   = dept_id,
                tenant_id = data["tenant_id"],
            )

        user = UserModel(**data)
        self.session.add(user)
        return user

    async def update(self, user_id: UUID, data: dict) -> UserModel | None:
        """
        Updates user fields. Only keys present in data are updated (exclude_unset pattern).

        If dept_id is being changed, performs the same tenant integrity check as create():
        verifies the new dept belongs to the same tenant as the user.
        """
        user = await self.get_by_id(user_id)
        if not user:
            return None

        if "dept_id" in data and data["dept_id"] is not None:
            await self._verify_dept_belongs_to_tenant(
                dept_id   = data["dept_id"],
                tenant_id = user.tenant_id,
            )

        _UPDATABLE = frozenset({
            "role", "dept_id", "is_active", "force_password_change", "password_hash",
        })
        for key, value in data.items():
            if key not in _UPDATABLE:
                raise ValueError(f"Field '{key}' cannot be updated via update().")
            setattr(user, key, value)

        return user

    async def list_by_tenant(
        self,
        tenant_id: UUID,
        dept_id:   UUID | None = None,
        role:      str  | None = None,
        is_active: bool | None = None,
        limit:     int  = 50,
        offset:    int  = 0,
    ) -> tuple[list[UserModel], int]:
        """Returns (users, total_count)."""
        query = select(UserModel).where(UserModel.tenant_id == tenant_id)

        if dept_id is not None:
            query = query.where(UserModel.dept_id == dept_id)
        if role is not None:
            query = query.where(UserModel.role == role)
        if is_active is not None:
            query = query.where(UserModel.is_active == is_active)

        count_query = select(func.count()).select_from(query.subquery())
        total       = await self.session.scalar(count_query) or 0

        query  = query.order_by(UserModel.created_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(query)
        users  = list(result.scalars().all())

        return users, total

    async def count_by_tenant(self, tenant_id: UUID) -> int:
        """Returns total user count for a tenant. Used by bootstrap to check if any users exist."""
        result = await self.session.execute(
            select(func.count()).where(UserModel.tenant_id == tenant_id)
        )
        return result.scalar_one() or 0

    async def count_active_admins(self, tenant_id: UUID) -> int:
        """
        Returns count of active admin users for a tenant.
        Used by last-admin protection before role change or deactivation.
        Uses ix_users_role_active composite index.
        """
        result = await self.session.execute(
            select(func.count()).where(
                UserModel.tenant_id == tenant_id,
                UserModel.role      == "ADMIN",
                UserModel.is_active == True,
            )
        )
        return result.scalar_one() or 0

    async def increment_token_version(self, user_id: UUID) -> int:
        """
        Atomically increments token_version by 1. Returns new version.
        All existing JWTs with the old ver claim become immediately invalid
        on their next request to the middleware.
        Called exclusively by AuthService.logout_all_sessions().
        """
        result = await self.session.execute(
            update(UserModel)
            .where(UserModel.id == user_id)
            .values(token_version=UserModel.token_version + 1)
            .returning(UserModel.token_version)
        )
        row = result.fetchone()
        return row[0] if row else 0

    async def update_last_login(self, user_id: UUID) -> None:
        """
        Sets last_login_at = NOW().
        Called in the same DB transaction as refresh token creation in login().
        """
        await self.session.execute(
            update(UserModel)
            .where(UserModel.id == user_id)
            .values(last_login_at=datetime.utcnow())
        )

    # ── Private helpers ────────────────────────────────────────────────────────

    async def _verify_dept_belongs_to_tenant(
        self,
        dept_id:   UUID,
        tenant_id: UUID,
    ) -> None:
        """
        Verifies that a department belongs to the specified tenant.
        Raises ValueError if the department does not exist under that tenant.
        Called on every create/update that sets dept_id — prevents cross-tenant
        data linkage even if the DB-level composite FK is not yet enforced.
        """
        result = await self.session.execute(
            select(DepartmentModel.id).where(
                DepartmentModel.id        == dept_id,
                DepartmentModel.tenant_id == tenant_id,
            )
        )
        if result.scalar_one_or_none() is None:
            raise ValueError(
                f"Department {dept_id} does not belong to tenant {tenant_id}. "
                "Cannot assign user to a department from a different tenant."
            )
