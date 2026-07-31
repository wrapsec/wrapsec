# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration test for GET /v1/capabilities.

In the OSS edition (no plugins installed) the endpoint reports edition "oss"
and an empty capability set -- the signal the dashboard uses to hide paid UI.
"""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_capabilities_endpoint_reports_oss_edition(client, admin_jwt_headers):
    r = await client.get("/v1/capabilities", headers=admin_jwt_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["edition"] == "oss"
    assert body["capabilities"] == []
