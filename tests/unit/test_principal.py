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
    key.key_id    = "wwsk_live_testkey123"
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


# ── has_permission — v1 guard ──────────────────────────────────────────────────

def test_has_permission_raises_not_implemented_in_v1():
    """has_permission() must NOT be callable in v1 — fail loud."""
    p = Principal(
        id="u1", type=PrincipalType.USER, tenant_id="t1", dept_id=None,
        roles=["ADMIN"], permissions=["*"], is_admin=True,
    )
    with pytest.raises(NotImplementedError):
        p.has_permission("scan:read")


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
    # principal.id = str(user.id) — prefixing to "user:{uuid}" done in middleware
    assert principal.id == str(user.id)


def test_api_key_principal_id_is_key_id():
    key       = _make_api_key_model()
    principal = build_principal_from_api_key(key)
    # principal.id = key.key_id — prefixing to "key:{key_id}" done in middleware
    assert principal.id == key.key_id
