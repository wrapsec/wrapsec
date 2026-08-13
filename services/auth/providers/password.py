# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
PasswordAuthProvider -- verifies email + password against the users table.

Owns the credential-specific parts of login():
  - email normalisation
  - DB lookup
  - password verify (Argon2id default, legacy bcrypt supported via passlib)
  - timing equalisation on user-not-found (verify_dummy)
  - transparent rehash on next successful login for deprecated schemes

Does NOT own lockout, active-user check, session issuance, or auth_event
logging -- those live in AuthService because they apply regardless of
which provider was used.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from services.auth.providers.base import AuthenticationOutcome, AuthProvider

logger = logging.getLogger("wrapsec.auth.password")


class PasswordAuthProvider(AuthProvider):

    @property
    def name(self) -> str:
        return "password"

    async def authenticate(
        self,
        credentials: dict[str, Any],
        db:          AsyncSession,
    ) -> AuthenticationOutcome:
        from db.repositories.user import UserRepository
        from services.auth.password import (
            hash_password,
            needs_rehash,
            normalize_email,
            verify_dummy,
            verify_password,
        )

        email    = normalize_email(credentials["email"])
        password = credentials["password"]

        user_repo = UserRepository(db)
        user      = await user_repo.get_by_email(email)

        if not user:
            # Timing equalisation: dummy hash verify so the not-found path
            # takes ~the same time as the wrong-password path.
            verify_dummy()
            return AuthenticationOutcome(failure_reason="user_not_found")

        if not verify_password(password, user.password_hash):
            return AuthenticationOutcome(
                resolved_user  = user,
                failure_reason = "invalid_password",
            )

        # Transparent password-hash upgrade (B6): if the stored hash uses
        # a deprecated scheme, rewrite it with Argon2id now that we hold
        # the plaintext. Silent on failure -- rehash errors must not deny
        # a valid login.
        if needs_rehash(user.password_hash):
            try:
                new_hash = hash_password(password)
                await user_repo.update(user.id, {"password_hash": new_hash})
                logger.info(
                    "auth_event PASSWORD_HASH_UPGRADED user_id=%s scheme=argon2id",
                    user.id,
                )
            except Exception as exc:
                logger.warning(
                    "auth_event PASSWORD_HASH_UPGRADE_FAILED user_id=%s error=%s",
                    user.id, exc,
                )

        return AuthenticationOutcome(user=user)
