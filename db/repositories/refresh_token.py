# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from datetime import datetime, timedelta
from typing import cast
from uuid import UUID

from sqlalchemy import CursorResult, delete, select, update

from db.models import RefreshTokenModel
from db.repositories.base import BaseRepository
from services.time import utc_now


class RefreshTokenRepository(BaseRepository):

    async def create(
        self,
        user_id:       UUID,
        token_hash:    str,
        expires_at:    datetime,
        token_version: int,
    ) -> RefreshTokenModel:
        """
        Inserts a new active refresh token row.

        token_version REQUIRED - must be user.token_version at time of issuance.
        Stored so the refresh flow can detect session invalidation:
            if token_rec.token_version != user.token_version -> SESSION_INVALIDATED.
        Caller owns the transaction - no commit here.
        """
        record = RefreshTokenModel(
            user_id       = user_id,
            token_hash    = token_hash,
            expires_at    = expires_at,
            token_version = token_version,
        )
        self.session.add(record)
        return record

    async def get_by_hash(self, token_hash: str) -> RefreshTokenModel | None:
        """
        Looks up an active (non-revoked, non-expired) refresh token by its SHA-256 hash.

        Uses SELECT ... FOR UPDATE to prevent race conditions on parallel refresh
        requests with the same token:
            Request A: acquires row lock -> proceeds -> revokes old -> creates new -> commits
            Request B: blocks until A commits -> sees revoked_at IS NOT NULL -> returns None -> 401

        Returns None if:
        - Token not found
        - revoked_at IS NOT NULL (already revoked)
        - expires_at < NOW() (expired)
        """
        result = await self.session.execute(
            select(RefreshTokenModel)
            .where(
                RefreshTokenModel.token_hash == token_hash,
                RefreshTokenModel.revoked_at.is_(None),
                RefreshTokenModel.expires_at > utc_now(),
            )
            .with_for_update()
        )
        return result.scalar_one_or_none()

    async def revoke(self, token_hash: str) -> None:
        """
        Sets revoked_at = NOW() on the matching token.
        Idempotent - safe to call if already revoked (UPDATE affects 0 rows, no error).
        Caller owns the transaction - no commit here.
        """
        await self.session.execute(
            update(RefreshTokenModel)
            .where(RefreshTokenModel.token_hash == token_hash)
            .values(revoked_at=utc_now())
        )

    async def revoke_all_for_user(self, user_id: UUID) -> int:
        """
        Revokes all active (revoked_at IS NULL) tokens for a user.
        Returns count of rows updated.
        Called exclusively by AuthService.logout_all_sessions().
        Caller owns the transaction - no commit here.
        """
        result = await self.session.execute(
            update(RefreshTokenModel)
            .where(
                RefreshTokenModel.user_id    == user_id,
                RefreshTokenModel.revoked_at.is_(None),
            )
            .values(revoked_at=utc_now())
        )
        return cast(CursorResult, result).rowcount

    async def cleanup_expired(self) -> int:
        """
        Deletes expired refresh tokens. Two clauses - both run every call.

        Clause 1 (primary - preserves recent audit trail):
            DELETE WHERE expires_at < NOW() AND revoked_at IS NOT NULL
            Keeps: expired-but-active (failed naturally, audit value remains)
            Keeps: revoked-but-not-expired (recent termination, investigation value)
            Deletes: BOTH expired AND explicitly revoked - audit value exhausted.

        Clause 2 (secondary - prevents unbounded table growth):
            DELETE WHERE expires_at < NOW() - 90 days
            Deletes ALL tokens older than 3x the refresh token lifetime (30 days).
            Covers users who abandoned sessions without ever logging out.
            At 90 days, audit value is exhausted regardless of revocation state.

        Combined: no token older than 90 days survives.
        Recently expired tokens preserved until also revoked or age out.

        Returns total deleted rows from both clauses combined.
        Caller owns the transaction - no commit here.
        """
        now              = utc_now()
        cutoff_secondary = now - timedelta(days=90)

        # Clause 1 - expired AND revoked
        result1 = await self.session.execute(
            delete(RefreshTokenModel).where(
                RefreshTokenModel.expires_at < now,
                RefreshTokenModel.revoked_at.is_not(None),
            )
        )

        # Clause 2 - anything older than 90 days regardless of revocation state
        result2 = await self.session.execute(
            delete(RefreshTokenModel).where(
                RefreshTokenModel.expires_at < cutoff_secondary,
            )
        )

        return cast(CursorResult, result1).rowcount + cast(CursorResult, result2).rowcount
