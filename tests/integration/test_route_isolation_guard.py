# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Route-introspection isolation guard (1.7 -- the correctness gate).

Every HTTP route must be consciously classified into exactly one bucket:

  TENANT_SCOPED     -- returns/mutates tenant data; MUST be isolated to the
                       caller's tenant (covered by the cross-tenant tests in
                       test_cross_tenant_isolation.py and friends).
  PLATFORM_OPERATOR -- cross-tenant by design; gated by require_platform_operator.
  PUBLIC            -- no authentication (allowlisted in the auth middleware).
  SELF_OR_NON_DATA  -- authenticated but not tenant-leakable data (self profile,
                       static lists, deployment/platform config, health).

This test fails when a route exists that is not in any bucket (a new route
silently skipping isolation review) or when a bucket lists a route that no
longer exists (the matrix drifting stale). Adding a route forces a deliberate
classification -- if it is tenant data, it belongs in TENANT_SCOPED and needs a
cross-tenant test.

Plugin note (P4): a plugin that mounts a route lands here too; it must be added
to the appropriate bucket, which is what makes the plugin isolation contract
structural rather than a promise.
"""
import pytest

# -- Buckets (the isolation matrix) --------------------------------------------

PUBLIC = {
    "/docs", "/docs/oauth2-redirect", "/openapi.json", "/redoc",
    "/health", "/health/live", "/health/ready", "/metrics",
    "/v1/capabilities",
    "/v1/setup", "/v1/setup/status",
    "/v1/auth/login", "/v1/auth/refresh",
}

SELF_OR_NON_DATA = {
    "/v1/auth/me", "/v1/auth/logout", "/v1/auth/change-password",
    "/health/config",                          # caller's own resolved config
    "/v1/admin/webhooks/connector-types",      # static connector catalog
    "/v1/settings/proxy/health",               # provider reachability probe
    "/v1/admin/email/settings",                # deployment SMTP (platform_settings)
}

PLATFORM_OPERATOR = {
    "/v1/admin/tenants",
    "/v1/admin/tenants/{tenant_id}",
    "/v1/admin/tenants/{tenant_id}/suspend",
    "/v1/admin/tenants/{tenant_id}/reactivate",
    "/v1/admin/tenants/{tenant_id}/bootstrap-admin",
}

TENANT_SCOPED = {
    # API keys
    "/v1/keys", "/v1/keys/{key_id}", "/v1/keys/{key_id}/rotate",
    # Departments
    "/v1/admin/departments", "/v1/admin/departments/{dept_id}",
    "/v1/admin/departments/{dept_id}/policy",
    "/v1/admin/departments/{dept_id}/stats",
    "/v1/admin/departments/{dept_id}/policy/llm",
    "/v1/admin/departments/{dept_id}/policy/proxy",
    # Applications
    "/v1/admin/applications", "/v1/admin/applications/{app_id}",
    "/v1/admin/applications/{app_id}/policy",
    "/v1/admin/applications/{app_id}/policy/llm",
    "/v1/admin/applications/{app_id}/policy/proxy",
    # Users (memberships)
    "/v1/admin/users", "/v1/admin/users/{user_id}",
    "/v1/admin/users/{user_id}/reset-password",
    # Webhooks
    "/v1/admin/webhooks", "/v1/admin/webhooks/{endpoint_id}",
    "/v1/admin/webhooks/{endpoint_id}/pause",
    "/v1/admin/webhooks/{endpoint_id}/reactivate",
    "/v1/admin/webhooks/{endpoint_id}/rotate-secret",
    "/v1/admin/webhooks/{endpoint_id}/test",
    # Email audit
    "/v1/admin/email", "/v1/admin/email/{email_id}", "/v1/admin/email/summary",
    # Own tenant profile + usage aggregate
    "/v1/admin/tenant",
    "/v1/admin/tenant/usage",
    # Audit
    "/v1/audit/logs", "/v1/audit/analytics", "/v1/audit/attribution",
    "/v1/audit/by-source", "/v1/audit/export", "/v1/audit/stats",
    # Proxy interactions
    "/v1/proxy/interactions", "/v1/proxy/interactions/{trace_id}",
    # Tenant settings
    "/v1/settings/thresholds", "/v1/settings/layers", "/v1/settings/llm",
    "/v1/settings/rate_limit", "/v1/settings/retention", "/v1/settings/storage",
    "/v1/settings/admin_limits", "/v1/settings/proxy",
    # Gateway (scan + proxy) + agent runs
    "/v1/ai/request", "/v1/ai/scan-batch", "/v1/ai/requests/{trace_id}",
    "/v1/chat/completions",
    "/v1/agent-runs/{run_id}",
}

_CLASSIFIED = PUBLIC | SELF_OR_NON_DATA | PLATFORM_OPERATOR | TENANT_SCOPED


def _app_route_paths() -> set[str]:
    from api.main import app
    paths = set()
    for route in app.routes:
        path    = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if not path:
            continue
        if methods <= {"HEAD", "OPTIONS"}:
            continue
        paths.add(path)
    return paths


def test_every_route_is_classified_for_isolation():
    live = _app_route_paths()
    unclassified = live - _CLASSIFIED
    assert not unclassified, (
        "Unclassified routes -- add each to a bucket in this file. If it returns or "
        "mutates tenant data it belongs in TENANT_SCOPED and needs a cross-tenant "
        "test:\n  " + "\n  ".join(sorted(unclassified))
    )


def test_isolation_matrix_has_no_stale_entries():
    live = _app_route_paths()
    stale = _CLASSIFIED - live
    assert not stale, (
        "Isolation matrix lists routes that no longer exist -- remove them:\n  "
        + "\n  ".join(sorted(stale))
    )


@pytest.mark.parametrize("bucket_a, bucket_b, label", [
    (PUBLIC, TENANT_SCOPED, "PUBLIC/TENANT_SCOPED"),
    (PLATFORM_OPERATOR, TENANT_SCOPED, "PLATFORM_OPERATOR/TENANT_SCOPED"),
    (SELF_OR_NON_DATA, TENANT_SCOPED, "SELF_OR_NON_DATA/TENANT_SCOPED"),
    (PUBLIC, PLATFORM_OPERATOR, "PUBLIC/PLATFORM_OPERATOR"),
])
def test_buckets_are_disjoint(bucket_a, bucket_b, label):
    overlap = bucket_a & bucket_b
    assert not overlap, f"A route is in two buckets ({label}): {sorted(overlap)}"
