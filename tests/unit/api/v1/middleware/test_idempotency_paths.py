# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression tests for IDEMPOTENCY_PATHS.

F-10 regression: the proxy path (POST /v1/chat/completions) was NOT covered
by the idempotency middleware. A network hiccup + client retry could double-
charge the paid LLM provider. The scan path (/v1/ai/request) was already
covered.

The middleware treats IDEMPOTENCY_PATHS as an exact-match set. These tests
lock in the invariant that both gateway processing paths are members so a
future edit that renames or unmounts one is caught in review.
"""

from api.v1.middleware.idempotency import IDEMPOTENCY_PATHS


def test_proxy_completions_path_is_idempotent():
    """
    F-10 regression: /v1/chat/completions is the OpenAI-compatible proxy path
    that forwards to paid LLM providers. It MUST be a member of
    IDEMPOTENCY_PATHS so retries with the same Idempotency-Key replay the
    cached response instead of re-invoking the provider.
    """
    assert "/v1/chat/completions" in IDEMPOTENCY_PATHS, (
        "F-10 regression: /v1/chat/completions must be in IDEMPOTENCY_PATHS "
        "to prevent double-charging on client retry."
    )


def test_scan_only_path_is_idempotent():
    """/v1/ai/request is the scan-only path. Must remain idempotent."""
    assert "/v1/ai/request" in IDEMPOTENCY_PATHS


def test_paths_are_exact_match_not_prefix():
    """
    The middleware uses `request.url.path not in IDEMPOTENCY_PATHS` - an
    exact-match check, not a prefix check. This test documents the contract:
    a sibling path like /v1/ai/requesting must NOT be picked up.
    """
    assert "/v1/ai" not in IDEMPOTENCY_PATHS
    assert "/v1/chat" not in IDEMPOTENCY_PATHS
    assert "/v1/ai/requesting" not in IDEMPOTENCY_PATHS


def test_non_gateway_paths_are_not_idempotent():
    """
    Health, audit reads, and auth endpoints must not appear here - they are
    naturally idempotent (GETs) or intentionally side-effectful (POST /login
    must increment failed-attempt counters even on retry).
    """
    for path in (
        "/health",
        "/v1/audit/logs",
        "/v1/auth/login",
        "/v1/keys",
        "/v1/admin/departments",
    ):
        assert path not in IDEMPOTENCY_PATHS, (
            f"Non-gateway path {path} unexpectedly in IDEMPOTENCY_PATHS"
        )
