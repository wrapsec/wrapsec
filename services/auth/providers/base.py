# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
AuthProvider -- credential verification contract.

v1.1.0 (B4) extracts the credential-check step of login() into a
provider interface so v1.5.0 can add OIDC/SAML/SCIM providers without
touching AuthService.login(). Lockout, account-active checks, session
issuance, and auth_event logging stay in AuthService -- those concerns
apply regardless of how the user proved their identity.

Provider contract:
  authenticate(credentials, db) -> AuthenticationOutcome
    - Must be timing-safe against user enumeration. For password auth,
      that means running a dummy hash verify when the identifier is
      unknown so response time does not leak account existence.
    - Never raises for a bad credential -- returns
      AuthenticationOutcome(failure_reason=...). Real exceptions
      (DB down, malformed input) propagate as-is.
    - On success, returns AuthenticationOutcome(user=<User>). On
      failure with a known user (e.g. wrong password), also sets
      resolved_user so AuthService can log tenant_id and user_id.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession


@dataclass
class AuthenticationOutcome:
    """
    Result of a single credential-verification attempt.

    Exactly one of two states applies:
      - success: user is set, failure_reason is None
      - failure: failure_reason is set (user is None; resolved_user may
        carry the matched-but-not-authenticated user for logging)
    """
    user:            Any        = None
    resolved_user:   Any        = None
    failure_reason:  str | None = None

    @property
    def ok(self) -> bool:
        return self.user is not None and self.failure_reason is None


class AuthProvider(ABC):
    """
    Verifies a set of credentials and returns the authenticated user
    (or a structured failure). Providers are stateless and safe to
    reuse across requests.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for logs and metrics (e.g. 'password', 'oidc')."""

    @abstractmethod
    async def authenticate(
        self,
        credentials: dict[str, Any],
        db:          AsyncSession,
    ) -> AuthenticationOutcome:
        """
        Verify credentials against this provider's identity source.
        Must be timing-safe against user enumeration.
        """
