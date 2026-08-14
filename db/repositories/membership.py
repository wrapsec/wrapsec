# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from uuid import UUID

from sqlalchemy import func, select

from db.models import DepartmentModel, MembershipModel
from db.repositories.base import BaseRepository

_VALID_ROLES = ("ADMIN", "DEVELOPER", "VIEWER", "AUDITOR")


class MembershipRepository(BaseRepository):
    """
    Access to memberships (a user's role + departmental scope within a tenant).

    Enforces the same role/dept invariant as the historical per-user rule and the
    same cross-tenant dept integrity check, so a membership can never link a user
    to a department in a different tenant. Flush-only (callers commit), per the
    repository contract.
    """

    async def get_by_user_and_tenant(
        self, user_id: UUID, tenant_id: UUID
    ) -> MembershipModel | None:
        result = await self.session.execute(
            select(MembershipModel).where(
                MembershipModel.user_id   == user_id,
                MembershipModel.tenant_id == tenant_id,
            )
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: UUID) -> list[MembershipModel]:
        """All memberships a user holds, oldest first (stable order for a picker)."""
        result = await self.session.execute(
            select(MembershipModel)
            .where(MembershipModel.user_id == user_id)
            .order_by(MembershipModel.created_at.asc())
        )
        return list(result.scalars().all())

    async def get_by_id(self, membership_id: UUID) -> MembershipModel | None:
        result = await self.session.execute(
            select(MembershipModel).where(MembershipModel.id == membership_id)
        )
        return result.scalar_one_or_none()

    async def create(self, data: dict) -> MembershipModel:
        """
        Creates a membership.

        Required keys: user_id (UUID), tenant_id (UUID), role
        Optional keys: dept_id (UUID)

        Validations (mirror UserRepository.create, now scoped to the membership):
        1. role must be in the allowlist.
        2. role = ADMIN forbids dept_id; role IN (DEVELOPER, VIEWER) requires it;
           AUDITOR permits either.
        3. If dept_id is set, it must belong to the membership's tenant.
        """
        role    = data.get("role", "DEVELOPER")
        dept_id = data.get("dept_id")

        self._validate_role_dept(role, dept_id)
        if dept_id:
            await self._verify_dept_belongs_to_tenant(
                dept_id   = dept_id,
                tenant_id = data["tenant_id"],
            )

        membership = MembershipModel(**data)
        self.session.add(membership)
        return membership

    async def upsert_for_user(
        self, user_id: UUID, tenant_id: UUID, role: str, dept_id: UUID | None
    ) -> MembershipModel:
        """
        Creates the (user, tenant) membership or updates its role/dept to match.

        Transitional helper for the identity migrate phase: user-write paths call
        this so the membership stays in lockstep with the user row while both
        sources coexist. Same validation as create(). Flush-only.
        """
        self._validate_role_dept(role, dept_id)
        if dept_id:
            await self._verify_dept_belongs_to_tenant(dept_id, tenant_id)

        existing = await self.get_by_user_and_tenant(user_id, tenant_id)
        if existing is None:
            membership = MembershipModel(
                user_id=user_id, tenant_id=tenant_id, role=role, dept_id=dept_id
            )
            self.session.add(membership)
            return membership

        existing.role    = role
        existing.dept_id = dept_id
        return existing

    async def count_active_for_tenant(self, tenant_id: UUID) -> int:
        """Count of memberships in a tenant. Used by provisioning/bootstrap checks."""
        result = await self.session.execute(
            select(func.count()).where(MembershipModel.tenant_id == tenant_id)
        )
        return result.scalar_one() or 0

    # -- Private helpers --------------------------------------------------------

    @staticmethod
    def _validate_role_dept(role: str, dept_id: UUID | None) -> None:
        """Role allowlist + role/dept invariant (mirrors ck_memberships_dept_required)."""
        if role not in _VALID_ROLES:
            raise ValueError(
                f"Invalid role '{role}'. Must be ADMIN, DEVELOPER, VIEWER, or AUDITOR."
            )
        if role == "ADMIN" and dept_id:
            raise ValueError("ADMIN memberships must not have a dept_id.")
        if role in ("DEVELOPER", "VIEWER") and not dept_id:
            raise ValueError(f"dept_id is required for role '{role}'.")

    async def _verify_dept_belongs_to_tenant(
        self, dept_id: UUID, tenant_id: UUID
    ) -> None:
        """
        Verifies a department belongs to the tenant. Raises ValueError otherwise.
        Prevents cross-tenant data linkage through a bad dept_id on a membership.
        """
        result = await self.session.execute(
            select(DepartmentModel.id).where(
                DepartmentModel.id        == dept_id,
                DepartmentModel.tenant_id == tenant_id,
            )
        )
        if result.scalar_one_or_none() is None:
            raise ValueError(
                f"Department {dept_id} does not belong to tenant {tenant_id}."
            )
