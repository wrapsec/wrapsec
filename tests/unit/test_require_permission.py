# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
require_permission (Phase 2, 2.6): permission-gated dependency. Denies trial keys
outright (they otherwise inherit DEVELOPER perms) and any principal lacking the
required permission.
"""
import uuid
from unittest.mock import MagicMock

import pytest

from api.v1.dependencies.auth import require_permission
from errors.exceptions import ForbiddenError


def _req(*, principal_type="user", user_role=None, is_admin=False, key_type="live"):
    r = MagicMock()
    r.state.principal_type = principal_type
    r.state.user_role      = user_role
    r.state.is_admin       = is_admin
    r.state.key_type       = key_type
    r.state.tenant_id      = str(uuid.uuid4())
    r.state.key_id         = "user:x" if principal_type == "user" else "key:x"
    r.state.dept_id        = None
    r.state.key_name       = None
    return r


@pytest.mark.asyncio
async def test_developer_passes():
    p = await require_permission("settings:read")(_req(user_role="DEVELOPER"))
    assert p.has_permission("settings:read")


@pytest.mark.asyncio
async def test_auditor_passes():
    p = await require_permission("settings:read")(_req(user_role="AUDITOR"))
    assert p.has_permission("settings:read")


@pytest.mark.asyncio
async def test_viewer_denied():
    with pytest.raises(ForbiddenError):
        await require_permission("settings:read")(_req(user_role="VIEWER"))


@pytest.mark.asyncio
async def test_trial_key_denied_despite_developer_perms():
    # A trial API key inherits DEVELOPER permissions; the trial guard blocks it
    # regardless, so calibration data never leaks to a probationary key.
    with pytest.raises(ForbiddenError):
        await require_permission("settings:read")(_req(principal_type="api_key", key_type="trial"))


@pytest.mark.asyncio
async def test_live_key_passes():
    p = await require_permission("settings:read")(_req(principal_type="api_key", key_type="live"))
    assert p.has_permission("settings:read")


@pytest.mark.asyncio
async def test_admin_key_passes_via_wildcard():
    p = await require_permission("settings:read")(_req(principal_type="api_key", is_admin=True))
    assert p.is_admin
