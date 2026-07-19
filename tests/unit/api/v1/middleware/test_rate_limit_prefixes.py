# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression tests for api.v1.middleware.rate_limit.RATE_LIMITED_PREFIXES.

F-4 regression: the proxy endpoint (POST /v1/chat/completions) was omitted
from the rate-limit prefix set, leaving the paid-provider path with no
per-key rate limit - only the coarse nginx per-IP backstop. The dead
"/v1/scan" and "/v1/proxy" prefixes were also removed since neither
matches any registered route.

These tests lock in the invariant that gateway processing paths are covered
by RATE_LIMITED_PREFIXES so a future edit that renames or unmounts one is
caught in review.
"""

from api.v1.middleware.rate_limit import RATE_LIMITED_PREFIXES


def test_proxy_completions_path_is_rate_limited():
    """
    F-4 regression: /v1/chat/completions is the OpenAI-compatible proxy path
    that forwards to paid LLM providers. It MUST be covered by the per-key
    rate limit. Without this, a leaked live key can drive unbounded provider
    calls.
    """
    proxy_path = "/v1/chat/completions"
    assert proxy_path.startswith(RATE_LIMITED_PREFIXES), (
        f"Proxy path {proxy_path} not covered by RATE_LIMITED_PREFIXES="
        f"{RATE_LIMITED_PREFIXES}. A per-key rate limit will not apply, "
        f"leaving the paid-provider path exposed to unlimited invocation."
    )


def test_scan_only_path_is_rate_limited():
    """/v1/ai/request is the scan-only path. Must remain rate-limited."""
    scan_path = "/v1/ai/request"
    assert scan_path.startswith(RATE_LIMITED_PREFIXES)


def test_health_paths_are_not_rate_limited():
    """
    Health endpoints must not match the rate-limit prefix set - probes from
    k8s / uptime monitors would otherwise consume the caller's bucket.
    """
    for path in ("/health", "/health/live", "/health/ready"):
        assert not path.startswith(RATE_LIMITED_PREFIXES), (
            f"Health path {path} unexpectedly matches RATE_LIMITED_PREFIXES"
        )


def test_dashboard_read_paths_are_not_rate_limited():
    """
    Settings, audit reads, and auth endpoints intentionally sit outside the
    gateway rate limit (dashboard traffic should not exhaust an operator's
    per-key budget).
    """
    for path in (
        "/v1/audit/logs",
        "/v1/audit/stats",
        "/v1/settings/thresholds",
        "/v1/auth/login",
        "/v1/admin/departments",
        "/v1/keys",
    ):
        assert not path.startswith(RATE_LIMITED_PREFIXES), (
            f"Non-gateway path {path} unexpectedly matches RATE_LIMITED_PREFIXES"
        )
