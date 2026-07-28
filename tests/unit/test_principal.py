# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid
import pytest
from unittest.mock import MagicMock

from domain.entities.principal import (
    Principal,
    ROLE_PERMISSIONS,
    build_principal_from_user,
    build_principal_from_api_key,
)
from domain.enums import PrincipalType


def _make_user_model(role="DEVELOPER", dept_id=None, tenant_id=None):
    user = MagicMock()
    user.id        = uuid.uuid4()
    user.tenant_id = tenant_id or uuid.uuid4()
    user.dept_id   = dept_id
    user.email     = "test@example.com"
    user.role      = role
    return user


def _make_api_key_model(tenant_id=None, dept_id=None):
    key = MagicMock()
    key.key_id    = "wsk_live_testkey123"
    key.tenant_id = tenant_id or uuid.uuid4()
    key.dept_id   = dept_id
    return key


# ── has_role ───────────────────────────────────────────────────────────────────

def test_has_role_match():
    p = Principal(
        id="u1", type=PrincipalType.USER, tenant_id="t1", dept_id=None,
        roles=["ADMIN"], permissions=["*"], is_admin=True,
    )
    assert p.has_role("ADMIN") is True


def test_has_role_no_match():
    p = Principal(
        id="u1", type=PrincipalType.USER, tenant_id="t1", dept_id=None,
        roles=["DEVELOPER"], permissions=[], is_admin=False,
    )
    assert p.has_role("ADMIN") is False


def test_has_role_multiple_any_match():
    p = Principal(
        id="u1", type=PrincipalType.USER, tenant_id="t1", dept_id=None,
        roles=["DEVELOPER"], permissions=[], is_admin=False,
    )
    assert p.has_role("ADMIN", "DEVELOPER") is True


def test_has_role_multiple_no_match():
    p = Principal(
        id="u1", type=PrincipalType.USER, tenant_id="t1", dept_id=None,
        roles=["VIEWER"], permissions=[], is_admin=False,
    )
    assert p.has_role("ADMIN", "DEVELOPER") is False


# ── has_permission - wildcard matching ─────────────────────────────────────────

def _principal_with(permissions: list[str]) -> Principal:
    return Principal(
        id="u1", type=PrincipalType.USER, tenant_id="t1", dept_id=None,
        roles=["TEST"], permissions=permissions, is_admin=False,
    )


class TestHasPermissionStar:
    # "*" is the ADMIN grant. It must short-circuit every check.

    def test_star_matches_any_permission(self):
        p = _principal_with(["*"])
        assert p.has_permission("audit:read")     is True
        assert p.has_permission("scan:write")     is True
        assert p.has_permission("anything:goes")  is True


class TestHasPermissionExactMatch:

    def test_exact_permission_matches(self):
        p = _principal_with(["audit:read", "dashboard:read"])
        assert p.has_permission("audit:read") is True

    def test_missing_permission_does_not_match(self):
        p = _principal_with(["audit:read"])
        assert p.has_permission("audit:write") is False

    def test_empty_permission_returns_false(self):
        # Guards against accidental has_permission("") in callers -- an
        # empty string must never resolve to True even for "*" principals.
        p = _principal_with(["*"])
        assert p.has_permission("") is False


class TestHasPermissionSegmentWildcard:
    # Segment-wise wildcards are the same containment rule Casbin,
    # AWS IAM, and GCP IAM apply: len(parts) must match len(p_parts).

    def test_prefix_star_grants_sibling_actions(self):
        p = _principal_with(["scan:*"])
        assert p.has_permission("scan:read")  is True
        assert p.has_permission("scan:write") is True

    def test_prefix_star_does_not_grant_different_prefix(self):
        p = _principal_with(["scan:*"])
        assert p.has_permission("audit:read") is False

    def test_wildcard_length_must_match(self):
        # "scan:*" grants two-segment scan:X but NOT three-segment
        # scan:X:Y. The stricter model prevents accidental privilege
        # escalation via longer permission names.
        p = _principal_with(["scan:*"])
        assert p.has_permission("scan:read:sensitive") is False

    def test_three_segment_wildcard(self):
        p = _principal_with(["tool:db:*"])
        assert p.has_permission("tool:db:read")  is True
        assert p.has_permission("tool:db:write") is True
        assert p.has_permission("tool:api:read") is False


class TestHasPermissionForKnownRoles:
    # Locks in the ROLE_PERMISSIONS map so a future edit that trims a
    # scope from AUDITOR (say) breaks loudly.

    def test_auditor_can_read_settings_and_keys(self):
        p = _principal_with(ROLE_PERMISSIONS["AUDITOR"])
        assert p.has_permission("settings:read") is True
        assert p.has_permission("keys:read")     is True
        assert p.has_permission("audit:read")    is True
        assert p.has_permission("dashboard:read") is True

    def test_auditor_cannot_write(self):
        p = _principal_with(ROLE_PERMISSIONS["AUDITOR"])
        assert p.has_permission("settings:write") is False
        assert p.has_permission("keys:write")     is False
        assert p.has_permission("keys:delete")    is False

    def test_viewer_is_stricter_than_auditor(self):
        # This is the whole reason AUDITOR exists as a separate role.
        p = _principal_with(ROLE_PERMISSIONS["VIEWER"])
        assert p.has_permission("settings:read") is False
        assert p.has_permission("keys:read")     is False

    def test_developer_keys_wildcard_grants_write(self):
        p = _principal_with(ROLE_PERMISSIONS["DEVELOPER"])
        assert p.has_permission("keys:read")   is True
        assert p.has_permission("keys:write")  is True
        assert p.has_permission("keys:delete") is True

    def test_admin_star_grants_everything(self):
        p = _principal_with(ROLE_PERMISSIONS["ADMIN"])
        assert p.has_permission("settings:write") is True
        assert p.has_permission("tool:db:drop")   is True


# ── build_principal_from_user ──────────────────────────────────────────────────

def test_build_user_admin_dept_is_none():
    user      = _make_user_model(role="ADMIN", dept_id=None)
    principal = build_principal_from_user(user)
    assert principal.is_admin is True
    assert principal.dept_id is None
    assert principal.roles == ["ADMIN"]
    assert principal.type == PrincipalType.USER


def test_build_user_developer_has_dept():
    dept_id   = uuid.uuid4()
    user      = _make_user_model(role="DEVELOPER", dept_id=dept_id)
    principal = build_principal_from_user(user)
    assert principal.is_admin is False
    assert principal.dept_id == str(dept_id)
    assert principal.roles == ["DEVELOPER"]


def test_build_user_tenant_id_is_string():
    user      = _make_user_model()
    principal = build_principal_from_user(user)
    assert isinstance(principal.tenant_id, str)


def test_build_user_no_tenant_raises_value_error():
    user           = _make_user_model()
    user.tenant_id = None
    with pytest.raises(ValueError, match="tenant_id"):
        build_principal_from_user(user)


def test_build_user_email_set():
    user      = _make_user_model()
    principal = build_principal_from_user(user)
    assert principal.email == "test@example.com"


def test_build_user_permissions_from_role_map():
    user      = _make_user_model(role="DEVELOPER")
    principal = build_principal_from_user(user)
    assert principal.permissions == ROLE_PERMISSIONS["DEVELOPER"]


def test_build_user_auditor_tenant_wide_no_dept():
    # AUDITOR is dept-scope flexible: this is the tenant-wide variant.
    user      = _make_user_model(role="AUDITOR", dept_id=None)
    principal = build_principal_from_user(user)
    assert principal.is_admin is False
    assert principal.dept_id is None
    assert principal.roles == ["AUDITOR"]
    assert principal.permissions == ROLE_PERMISSIONS["AUDITOR"]


def test_build_user_auditor_dept_scoped():
    # AUDITOR can also be constrained to one department for large tenants
    # that want per-BU compliance leads. Mirrors AWS SecurityAudit at OU scope.
    dept_id   = uuid.uuid4()
    user      = _make_user_model(role="AUDITOR", dept_id=dept_id)
    principal = build_principal_from_user(user)
    assert principal.is_admin is False
    assert principal.dept_id == str(dept_id)
    assert principal.roles == ["AUDITOR"]


# ── build_principal_from_api_key ───────────────────────────────────────────────

def test_build_api_key_type_is_api_key():
    key       = _make_api_key_model()
    principal = build_principal_from_api_key(key)
    assert principal.type == PrincipalType.API_KEY


def test_build_api_key_is_not_admin():
    key       = _make_api_key_model()
    principal = build_principal_from_api_key(key)
    assert principal.is_admin is False


def test_build_api_key_tenant_id_is_real_uuid_string():
    """tenant_id must never be 'admin' or any placeholder string."""
    tenant_id = uuid.uuid4()
    key       = _make_api_key_model(tenant_id=tenant_id)
    principal = build_principal_from_api_key(key)
    assert principal.tenant_id == str(tenant_id)
    assert principal.tenant_id != "admin"


def test_build_api_key_no_tenant_raises_value_error():
    key           = _make_api_key_model()
    key.tenant_id = None
    with pytest.raises(ValueError, match="tenant_id"):
        build_principal_from_api_key(key)


def test_build_api_key_dept_id_none_when_absent():
    key       = _make_api_key_model(dept_id=None)
    principal = build_principal_from_api_key(key)
    assert principal.dept_id is None


def test_build_api_key_dept_id_string_when_present():
    dept_id   = uuid.uuid4()
    key       = _make_api_key_model(dept_id=dept_id)
    principal = build_principal_from_api_key(key)
    assert principal.dept_id == str(dept_id)


# ── key_id prefixing convention (enforced in middleware, documented here) ──────

def test_user_principal_id_is_uuid_string():
    user      = _make_user_model()
    principal = build_principal_from_user(user)
    # principal.id = str(user.id) - prefixing to "user:{uuid}" done in middleware
    assert principal.id == str(user.id)


def test_api_key_principal_id_is_key_id():
    key       = _make_api_key_model()
    principal = build_principal_from_api_key(key)
    # principal.id = key.key_id - prefixing to "key:{key_id}" done in middleware
    assert principal.id == key.key_id
