# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A policy that could not be resolved must not be enforced.

The resolver layers system defaults, stored tenant settings, then department and
application overrides. When any of those fails to load, the effective policy is
UNKNOWN -- not "the defaults". The tenant may have tightened its thresholds,
loosened them, or changed nothing, and a failed read cannot tell those apart.

Serving the defaults in that state silently relaxes every tenant that had
tightened, which is the direction that matters: it is the one case where the
customer explicitly asked for more strictness and quietly received less.

WHY AN EXCEPTION RATHER THAN A FLAG. A returned flag can be ignored by a caller
that never reads it, and the failure mode of ignoring it is to enforce under an
unverified policy -- the exact outcome being prevented. An exception cannot be
ignored by accident, and an enforcement path that does nothing about it fails
SAFE. `test_an_enforcement_caller_cannot_silently_receive_a_degraded_policy`
pins that property directly.
"""

from __future__ import annotations

import pytest

from errors.exceptions import PolicyResolutionDegraded
from services.policy_resolver import (
    resolve_policy,
    resolve_policy_for_preview,
    system_defaults,
)

_TENANT = "11111111-1111-1111-1111-111111111111"
_DEPT   = "22222222-2222-2222-2222-222222222222"
_APP    = "33333333-3333-3333-3333-333333333333"

_STORED = {
    "policy_thresholds": {"block_threshold": 0.55, "sanitize_threshold": 0.25},
    "detection_layers":  {"rule_enabled": True, "ml_enabled": True, "llm_enabled": True},
    "llm_settings":      {"provider": "stored-provider", "model": "stored-model"},
    "rate_limit":        {"per_minute": 999},
}


class _Boom(Exception):
    """Distinct from anything the resolver raises itself."""


def _settings_repo(fail: bool = False):
    class _Repo:
        def __init__(self, *a, **kw):
            pass

        async def get(self, *args, **kwargs):
            if fail:
                raise _Boom("simulated settings read failure")
            key = next((a for a in args if isinstance(a, str)), None) or kwargs.get("key")
            return dict(_STORED.get(key, {}))

    return _Repo


def _install(monkeypatch, *, settings_fail=False, dept_fail=False, app_fail=False):
    import db.repositories.settings as settings_repos
    import services.policy_resolver as resolver

    repo = _settings_repo(settings_fail)
    monkeypatch.setattr(settings_repos, "PlatformSettingsRepository", repo)
    monkeypatch.setattr(settings_repos, "TenantSettingsRepository",   repo)

    class _DeptRepo:
        def __init__(self, *a, **kw):
            pass

        async def get_by_id(self, *a, **kw):
            if dept_fail:
                raise _Boom("simulated department read failure")

    class _AppRepo:
        def __init__(self, *a, **kw):
            pass

        async def get_by_id(self, *a, **kw):
            if app_fail:
                raise _Boom("simulated application read failure")

    monkeypatch.setattr(resolver, "DepartmentRepository",  _DeptRepo)
    monkeypatch.setattr(resolver, "ApplicationRepository", _AppRepo)


# ── enforcement refuses ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_tenant_resolution_failure_refuses(monkeypatch):
    _install(monkeypatch, settings_fail=True)

    with pytest.raises(PolicyResolutionDegraded) as refused:
        await resolve_policy(db=object(), tenant_id=_TENANT)

    assert "tenant" in refused.value.failed_layers


@pytest.mark.asyncio
async def test_a_department_override_failure_refuses(monkeypatch):
    """Previously logged as a warning and treated as a successful resolution.

    A department override that failed to load may have TIGHTENED the policy, so
    continuing served the un-tightened base as though it were the resolved
    answer."""
    _install(monkeypatch, dept_fail=True)

    with pytest.raises(PolicyResolutionDegraded) as refused:
        await resolve_policy(db=object(), tenant_id=_TENANT, dept_id=_DEPT)

    assert "department" in refused.value.failed_layers


@pytest.mark.asyncio
async def test_an_application_override_failure_refuses(monkeypatch):
    _install(monkeypatch, app_fail=True)

    with pytest.raises(PolicyResolutionDegraded) as refused:
        await resolve_policy(db=object(), tenant_id=_TENANT, app_id=_APP)

    assert "application" in refused.value.failed_layers


# ── preview degrades, visibly ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_preview_returns_defaults_and_says_they_are_degraded(monkeypatch):
    _install(monkeypatch, settings_fail=True)

    policy, source, degraded = await resolve_policy_for_preview(
        db=object(), tenant_id=_TENANT,
    )

    assert degraded is True, "a degraded preview did not report itself as degraded"
    assert policy == system_defaults()
    assert source == "degraded", (
        "policy_source still names a real resolution layer, so a page rendering "
        "it cannot tell these defaults from a genuine resolution"
    )


@pytest.mark.asyncio
async def test_preview_reports_not_degraded_when_resolution_succeeds(monkeypatch):
    """The control. Without it a preview hard-coded to `degraded=True` would
    satisfy the test above."""
    _install(monkeypatch)

    policy, source, degraded = await resolve_policy_for_preview(
        db=object(), tenant_id=_TENANT,
    )

    assert degraded is False
    assert policy["thresholds"]["block"] == 0.55
    assert source != "degraded"


# ── the success path is unchanged ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_successful_resolution_is_unchanged(monkeypatch):
    _install(monkeypatch)

    policy, source = await resolve_policy(db=object(), tenant_id=_TENANT)

    assert policy["thresholds"]["block"]      == 0.55
    assert policy["thresholds"]["sanitize"]   == 0.25
    assert policy["rate_limit"]["per_minute"] == 999
    assert isinstance(source, str) and source


# ── the property the design rests on ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_an_enforcement_caller_cannot_silently_receive_a_degraded_policy(monkeypatch):
    """The invariant, stated as the thing a careless caller would do.

    A caller that ignores degradation entirely -- unpacks the tuple, reads the
    thresholds, enforces -- must not get a usable policy out of a failed
    resolution. If this ever returns instead of raising, every enforcement path
    in the API silently relaxes on a database blip.
    """
    _install(monkeypatch, settings_fail=True)

    careless_result = None
    try:
        careless_result, _source = await resolve_policy(db=object(), tenant_id=_TENANT)
    except PolicyResolutionDegraded:
        pass

    assert careless_result is None, (
        "resolve_policy RETURNED a policy for a failed resolution. A caller that "
        "does not check for degradation would now enforce under it."
    )


@pytest.mark.asyncio
async def test_the_refusal_carries_the_fail_closed_error_code():
    """It must land in the existing fail-closed vocabulary rather than a new
    parallel one, so a consumer branching on `error.code` sees the same class of
    event as a detector that could not run."""
    from errors.catalog import ErrorCode

    assert PolicyResolutionDegraded([]).code == ErrorCode.DETECTION_ERROR
    assert PolicyResolutionDegraded([]).status_code == 500
