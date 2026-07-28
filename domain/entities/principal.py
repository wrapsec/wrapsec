# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from domain.enums import PrincipalType

if TYPE_CHECKING:
    from db.models import APIKeyModel, UserModel

# ── Role -> permission strings ──────────────────────────────────────────────────
#
# Endpoint guards continue to use has_role() / require_role() for coarse
# access control; has_permission() is available for the fine-grained checks
# that landed with the AUDITOR role (settings:read, keys:read) where a
# VIEWER-vs-AUDITOR distinction matters more than a role label.
#
# AUDITOR is a read-only compliance role. It is strictly a superset of
# VIEWER (all VIEWER scopes plus settings:read and keys:read) so any policy
# that admits VIEWER also admits AUDITOR by construction.
#
ROLE_PERMISSIONS: dict[str, list[str]] = {
    "ADMIN":     ["*"],
    "DEVELOPER": ["scan:*", "audit:read", "settings:read", "keys:*", "dashboard:read"],
    "AUDITOR":   ["audit:read", "dashboard:read", "settings:read", "keys:read"],
    "VIEWER":    ["audit:read", "dashboard:read"],
}


@dataclass
class Principal:
    id:           str             # "user:{uuid}" | "key:{key_id}" | "key:admin"
    type:         PrincipalType
    tenant_id:    str             # NEVER None - enforced at construction (Layer 4)
    dept_id:      str | None      # None for ADMIN role only
    roles:        list[str]
    permissions:  list[str]       # from ROLE_PERMISSIONS - v2+ use only, not enforced in v1
    is_admin:     bool
    email:        str | None = None       # USER principals only
    # Phase 3 extension points - always None in v1
    agent_id:     str | None = None
    triggered_by: str | None = None

    def has_role(self, *roles: str) -> bool:
        """Check if principal has any of the specified roles. Used in all v1 guards."""
        return any(r in self.roles for r in roles)

    def has_permission(self, permission: str) -> bool:
        """
        Wildcard permission check.

        Matching rules:
            "*"         in permissions -> matches everything (ADMIN)
            exact match on the requested permission
            segment-wise wildcard: "scan:*" grants "scan:read", "scan:write";
            "tool:db:*" grants "tool:db:read", "tool:db:write"

        Segment lengths must match: "scan:*" does NOT grant "scan:read:sensitive"
        (that would require "scan:*:*" or similar). Broader matches are opt-in
        with an explicit extra segment, not accidental via a single trailing
        star.

        Empty permission strings and permissions containing "*" as a literal
        segment in the check argument are treated as no-match; callers should
        pass concrete permission strings like "settings:read".
        """
        if not permission:
            return False

        if "*" in self.permissions:
            return True
        if permission in self.permissions:
            return True

        parts = permission.split(":")
        for p in self.permissions:
            p_parts = p.split(":")
            if len(p_parts) != len(parts):
                continue
            if all(a == b or b == "*" for a, b in zip(parts, p_parts)):
                return True
        return False


# ── Builder functions ──────────────────────────────────────────────────────────

def build_principal_from_user(user: UserModel) -> Principal:
    """
    Builds Principal from UserModel after DB load.
    Called by JWT middleware path in api/v1/middleware/auth.py.

    Raises ValueError (NOT assert) if tenant_id is None.
    Using ValueError instead of assert: Python assert can be disabled
    with -O flag and must never be used for security checks.

    UUID/string boundary: DB returns UUID objects - cast to str here.
    All downstream code (request.state, JWT, logs) uses string tenant_id.
    """
    if not user.tenant_id:
        raise ValueError(
            f"User {user.id} has no tenant_id - cannot build Principal. "
            "This is a data integrity issue - investigate immediately."
        )
    return Principal(
        id          = str(user.id),
        type        = PrincipalType.USER,
        tenant_id   = str(user.tenant_id),
        dept_id     = str(user.dept_id) if user.dept_id else None,
        roles       = [user.role],
        permissions = ROLE_PERMISSIONS.get(user.role, []),
        is_admin    = (user.role == "ADMIN"),
        email       = user.email,
    )


def build_principal_from_api_key(key: APIKeyModel) -> Principal:
    """
    Builds Principal from APIKeyModel after DB load.
    Called by API key middleware path for non-admin application keys.

    The hardcoded admin key (wrapsec_admin_key) is NEVER in the api_keys
    table and is handled separately by _authenticate_admin_key() in middleware,
    which fetches the default tenant from DB directly.
    This function is NEVER called for the admin key.

    All DB rows in api_keys are non-admin application keys - all must have
    tenant_id after the NOT NULL migration in add_users.sql.
    Raises ValueError (NOT assert) if tenant_id is missing.
    """
    if not key.tenant_id:
        raise ValueError(
            f"API key {key.key_id} has no tenant_id - cannot build Principal. "
            "Run migration add_users.sql to enforce NOT NULL on api_keys.tenant_id."
        )
    return Principal(
        id          = key.key_id,   # prefixed to "key:{key_id}" at request.state level in middleware
        type        = PrincipalType.API_KEY,
        tenant_id   = str(key.tenant_id),
        dept_id     = str(key.dept_id) if key.dept_id else None,
        roles       = ["DEVELOPER"],
        permissions = ROLE_PERMISSIONS.get("DEVELOPER", []),
        is_admin    = False,
    )
