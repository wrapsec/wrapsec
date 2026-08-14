# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from uuid import UUID

from sqlalchemy import func, select, update

from db.models import UserModel
from db.repositories.base import BaseRepository
from services.time import utc_now


class UserRepository(BaseRepository):
    """
    User identity (D2 Option B). A user row carries credentials and account state
    only -- tenant, role, and departmental scope live on MembershipRepository.
    Email is globally unique (ux_users_email_lower).
    """

    async def get_by_email(self, email: str) -> UserModel | None:
        """
        Case-insensitive email lookup using LOWER() to match ux_users_email_lower index.

        CRITICAL: ALWAYS use func.lower() in the WHERE clause.
        NEVER use WHERE email = :email - that query does NOT use the index
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
        Creates a user identity.

        Required keys: email (pre-normalized), password_hash
        Optional keys: force_password_change (bool)

        Role and departmental scope are NOT set here -- the caller creates the
        matching membership (MembershipRepository) in the same transaction.
        """
        user = UserModel(
            email                 = data["email"],
            password_hash         = data["password_hash"],
            force_password_change = data.get("force_password_change", False),
        )
        self.session.add(user)
        return user

    async def update(self, user_id: UUID, data: dict) -> UserModel | None:
        """
        Updates account state. Only keys present in data are updated.

        Authz (role/dept) is not updatable here -- it lives on the membership.
        """
        user = await self.get_by_id(user_id)
        if not user:
            return None

        _UPDATABLE = frozenset({
            "is_active", "force_password_change", "password_hash", "locale",
        })
        for key, value in data.items():
            if key not in _UPDATABLE:
                raise ValueError(f"Field '{key}' cannot be updated via update().")
            setattr(user, key, value)

        return user

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
            .values(last_login_at=utc_now())
        )
