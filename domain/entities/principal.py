# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from __future__ import annotations

from dataclasses import dataclass

from domain.enums import PrincipalType

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
