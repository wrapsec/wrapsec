# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Settings-read RBAC (Phase 2, 2.6). The /v1/settings/* GET family requires the
settings:read permission -- the first place ROLE_PERMISSIONS is load-bearing.
DEVELOPER and AUDITOR hold it; VIEWER does not. Stops disclosure of the exact
thresholds/layer calibration data to a read-only principal.
"""
import pytest

_SETTINGS_GETS = [
    "/v1/settings/thresholds", "/v1/settings/layers", "/v1/settings/llm",
    "/v1/settings/rate_limit", "/v1/settings/retention", "/v1/settings/storage",
    "/v1/settings/admin_limits",
]


def _bearer(t):
    return {"Authorization": f"Bearer {t}"}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", _SETTINGS_GETS)
async def test_developer_may_read_settings(auth_client, auth_setup, path):
    assert (await auth_client.get(path, headers=_bearer(auth_setup["dev_token"]))).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("path", _SETTINGS_GETS)
async def test_viewer_may_not_read_settings(auth_client, auth_setup, path):
    r = await auth_client.get(path, headers=_bearer(auth_setup["viewer_token"]))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_still_reads_settings(auth_client, auth_setup):
    assert (await auth_client.get("/v1/settings/thresholds",
                                  headers=_bearer(auth_setup["admin_token"]))).status_code == 200
