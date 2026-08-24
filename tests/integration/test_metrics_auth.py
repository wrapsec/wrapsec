# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
/metrics must not be readable without the secret.

The guard was recorded as verified by inspection. Removing it entirely left the
whole suite green, so nothing would have reported the endpoint becoming public.
What it exposes is the operational shape of the deployment -- decision counts by
type, per-layer scores, latencies, key types -- which is the same detection
signal the scan response withholds from callers without `settings:read`, in
aggregate and without authentication.

The route is registered on the app directly rather than under /v1, so it does
not pass through AuthMiddleware and carries its own check. That is exactly why
it needs its own test: no route-level guard covers it.
"""

import pytest

from config.settings import get_settings


def _expected_token() -> str:
    s = get_settings()
    return s.metrics_token or s.admin_api_key


@pytest.mark.asyncio
async def test_metrics_requires_a_token(client):
    resp = await client.get("/metrics")
    assert resp.status_code == 401, (
        f"/metrics answered without a credential: {resp.status_code}"
    )


@pytest.mark.asyncio
async def test_metrics_rejects_a_wrong_token(client):
    resp = await client.get(
        "/metrics", headers={"Authorization": "Bearer not-the-configured-secret"},
    )
    assert resp.status_code == 401, (
        f"/metrics accepted a wrong token: {resp.status_code}"
    )


@pytest.mark.asyncio
async def test_metrics_rejects_an_empty_bearer(client):
    """
    An empty token must not compare equal to anything. The guard checks for a
    present token before comparing, and a blank one reaching `compare_digest`
    would be a different bug than a wrong one.
    """
    resp = await client.get("/metrics", headers={"Authorization": "Bearer "})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_metrics_serves_the_correct_token(client):
    """
    The other direction: a guard that rejected everything would satisfy the
    three above while breaking every scrape.
    """
    resp = await client.get(
        "/metrics", headers={"Authorization": f"Bearer {_expected_token()}"},
    )
    assert resp.status_code == 200, (
        f"/metrics refused the configured token: {resp.status_code} {resp.text[:200]}"
    )
    assert "wrapsec" in resp.text or "python_info" in resp.text, (
        "the body does not look like a metrics exposition"
    )
