# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
M9 regression: the admin auth dependencies must reject API-key principals.

Threat model: the dashboard's /api/proxy/[...path] BFF forwards whichever
credential the browser holds (JWT or API key cookie). If a user with only
an app API key crafts a request straight to an admin endpoint, the backend
must return 403 - the UI hiding admin controls is not a security boundary.

These tests exercise the require_admin, require_role, require_jwt, and
require_any_admin dependencies directly, without spinning up FastAPI, by
constructing a mock Request with the state fields those dependencies read.
"""

from types import SimpleNamespace
import pytest

from api.v1.dependencies.auth import (
    require_admin, require_role, require_jwt, require_any_admin,
)
from errors.exceptions import ForbiddenError


def _mock_request(principal_type: str, is_admin: bool = False, role: str | None = None):
    """
    Build a Request-like object with the exact request.state fields that
    _get_principal_from_state reads. Using SimpleNamespace instead of
    MagicMock so unset attributes raise AttributeError rather than returning
    a truthy MagicMock - which would defeat the point of these tests.
    """
    state = SimpleNamespace(
        principal_type = principal_type,
        tenant_id      = "11111111-1111-1111-1111-111111111111",
        key_id         = "test-key",
        dept_id        = None,
        user_role      = role,
        is_admin       = is_admin,
        key_name       = "test",
    )
    return SimpleNamespace(state=state)


@pytest.mark.asyncio
async def test_require_admin_rejects_api_key():
    dep = require_admin()
    with pytest.raises(ForbiddenError):
        await dep(_mock_request("api_key", is_admin=False, role="DEVELOPER"))


@pytest.mark.asyncio
async def test_require_admin_rejects_api_key_even_if_flagged_admin():
    """
    Defence in depth: if a bug ever set is_admin=True on an API-key principal,
    require_admin should still refuse because principal_type != 'user'.
    """
    dep = require_admin()
    with pytest.raises(ForbiddenError):
        await dep(_mock_request("api_key", is_admin=True, role="ADMIN"))


@pytest.mark.asyncio
async def test_require_role_rejects_api_key():
    dep = require_role("ADMIN", "DEVELOPER")
    with pytest.raises(ForbiddenError):
        await dep(_mock_request("api_key", role="DEVELOPER"))


@pytest.mark.asyncio
async def test_require_jwt_rejects_api_key():
    with pytest.raises(ForbiddenError):
        await require_jwt(_mock_request("api_key"))


@pytest.mark.asyncio
async def test_require_admin_accepts_jwt_admin():
    dep = require_admin()
    p = await dep(_mock_request("user", is_admin=True, role="ADMIN"))
    assert p is not None


@pytest.mark.asyncio
async def test_require_admin_rejects_jwt_non_admin():
    dep = require_admin()
    with pytest.raises(ForbiddenError):
        await dep(_mock_request("user", is_admin=False, role="DEVELOPER"))


@pytest.mark.asyncio
async def test_require_any_admin_rejects_non_admin_api_key():
    """
    require_any_admin() intentionally accepts admin API keys (the hardcoded
    ADMIN_API_KEY) alongside JWT admins. But a *regular* app API key from
    the api_keys table has is_admin=False - it must still get 403.
    """
    dep = require_any_admin()
    with pytest.raises(ForbiddenError):
        await dep(_mock_request("api_key", is_admin=False))


@pytest.mark.asyncio
async def test_require_any_admin_accepts_admin_api_key():
    dep = require_any_admin()
    p   = await dep(_mock_request("api_key", is_admin=True))
    assert p is not None
