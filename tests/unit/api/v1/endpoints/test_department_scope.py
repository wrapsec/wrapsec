# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression tests for the non-admin department scope helper.

F-3 regression: get_department_stats / get_department_policy / get_department
gated only on tenant match, not per-department scope. A DEVELOPER/VIEWER key
scoped to dept A could request dept B (same tenant) and receive B's aggregated
audit stats and resolved policy. list_departments already scoped correctly;
these three endpoints did not.

The fix adds a _require_dept_scope helper that returns NotFoundError (not
ForbiddenError) for non-admin callers requesting a dept other than their own.
NotFoundError matches the behaviour of get_scoped_audit_record and prevents
enumeration of sibling departments by response-code probing.
"""

from types import SimpleNamespace

import pytest

from api.v1.endpoints.departments import _require_dept_scope
from errors.exceptions import NotFoundError


def _request(is_admin: bool, dept_id: str | None):
    """Minimal request stub - only the state attributes the helper reads."""
    return SimpleNamespace(state=SimpleNamespace(
        is_admin = is_admin,
        dept_id  = dept_id,
    ))


# ── admin ───────────────────────────────────────────────────────────────────

def test_admin_can_read_any_department():
    """Admin bypasses the scope check regardless of their own dept_id."""
    req = _request(is_admin=True, dept_id="dept-A")
    # Must not raise even for a different dept_id.
    _require_dept_scope(req, dept_id="dept-B")


def test_admin_without_dept_id_still_bypasses():
    """
    Admins are often not scoped to any dept (tenant-wide access). The scope
    check must not trip on a None dept_id when the caller is admin.
    """
    req = _request(is_admin=True, dept_id=None)
    _require_dept_scope(req, dept_id="dept-anything")


# ── non-admin, own dept ─────────────────────────────────────────────────────

def test_non_admin_can_read_own_department():
    """
    A non-admin scoped to dept A must be able to read dept A. This is the
    intended path - the fix must not break it.
    """
    req = _request(is_admin=False, dept_id="dept-A")
    _require_dept_scope(req, dept_id="dept-A")


# ── non-admin, sibling dept - the actual F-3 case ───────────────────────────

def test_non_admin_cannot_read_sibling_department():
    """
    F-3 core regression: a non-admin scoped to dept A must be denied when
    requesting dept B. NotFoundError (not ForbiddenError) is deliberate so
    the caller cannot enumerate sibling departments by probing response codes.
    """
    req = _request(is_admin=False, dept_id="dept-A")
    with pytest.raises(NotFoundError):
        _require_dept_scope(req, dept_id="dept-B")


def test_non_admin_with_no_dept_id_cannot_read_any_department():
    """
    A non-admin whose principal has no dept_id is not authorised to read any
    dept - they cannot substitute an empty dept_id for tenant-wide access.
    """
    req = _request(is_admin=False, dept_id=None)
    with pytest.raises(NotFoundError):
        _require_dept_scope(req, dept_id="dept-A")


def test_non_admin_with_empty_string_dept_id_cannot_read_any_department():
    """
    An empty-string dept_id in principal state must also be treated as
    unauthorised - guards against a middleware bug that sets dept_id="".
    """
    req = _request(is_admin=False, dept_id="")
    with pytest.raises(NotFoundError):
        _require_dept_scope(req, dept_id="dept-A")


def test_uuid_string_comparison_case_sensitive():
    """
    dept_id comparison is exact string match on the caller's own dept_id
    against the URL path segment. Case mismatch must NOT authorise access -
    catches a future edit that lowercases either side.
    """
    req = _request(is_admin=False, dept_id="ABC-123")
    with pytest.raises(NotFoundError):
        _require_dept_scope(req, dept_id="abc-123")
