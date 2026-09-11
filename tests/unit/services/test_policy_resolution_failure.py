# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A failed policy resolution must produce the DEFAULTS, not a mixture.

WHAT THESE PROVE, precisely. They do NOT reproduce a live defect: the resolver
hoists all four stored-settings reads above the assignments that consume them,
so a read failure today lands before any layer is written and even the old
in-place code returned clean defaults. These tests were written expecting a
mixture, passed against the unfixed resolver, and the statement order is why.

That is the point of keeping them. The invariant "a failed resolution yields
exactly the system defaults" currently holds because of where four lines happen
to sit, not because anything enforces it. Move a read below an assignment, or
add a fifth setting read where it is used, and a failure starts returning a
blend of this tenant's settings and the system's -- with the split determined by
which database read failed, which is not reproducible from the response and not
something a caller can reason about.

The resolver now builds a working copy and commits it only on success, making
the invariant structural. These tests pin it so a later reordering fails here
rather than in production.

AFTER THE FAIL-CLOSED CHANGE the property is guarded twice over, and these tests
were re-pointed rather than relaxed. `resolve_policy` no longer returns anything
on a degraded resolution -- it raises, and enforcement refuses. The only entry
point that still returns on failure is the preview one, which builds fresh
defaults of its own. So the "never a mixture" guarantee now rests on two
independent mechanisms, and this file exercises it through the surviving one.
"""

from __future__ import annotations

import pytest

from services.policy_resolver import resolve_policy_for_preview, system_defaults


class _Boom(Exception):
    """Distinct from anything the resolver raises itself."""


# Each stored key the resolver reads, in the order it reads them, with a value
# that DIFFERS from the system default. The values matter: the resolver guards
# every layer with `if stored_x:`, so a mock returning empty dicts applies
# nothing and no partial merge can form -- a test built that way passes against
# the broken code and proves nothing. It has to feed real settings for the
# layers BEFORE the failure.
_STORED = {
    "policy_thresholds": {"block_threshold": 0.55, "sanitize_threshold": 0.25},
    "detection_layers":  {"rule_enabled": False, "ml_enabled": False, "llm_enabled": False},
    "llm_settings":      {"provider": "stored-provider", "model": "stored-model"},
    "rate_limit":        {"per_minute": 999},
}
_ORDER = ("policy_thresholds", "detection_layers", "llm_settings", "rate_limit")


def _repo_failing_on(key_to_fail: str | None):
    """A settings repository that serves real values until `key_to_fail`."""

    class _Repo:
        def __init__(self, *a, **kw):
            pass

        async def get(self, *args, **kwargs):
            key = next((a for a in args if isinstance(a, str)), None) or kwargs.get("key")
            if key is not None and key == key_to_fail:
                raise _Boom(f"simulated read failure for {key}")
            return dict(_STORED.get(key, {}))

    return _Repo


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_key", _ORDER[1:])
async def test_a_failure_after_an_applied_layer_returns_exactly_the_defaults(monkeypatch, fail_key):
    """The layers before `fail_key` load successfully and carry non-default
    values, so the broken resolver has already written them into the returned
    dict by the time the failure lands.

    Parametrised from the SECOND key onwards: failing on the first key means
    nothing was applied yet, which the old code also handled correctly. Those
    cases cannot distinguish the fix and are covered by the separate control.
    """
    import db.repositories.settings as settings_repos

    repo = _repo_failing_on(fail_key)
    monkeypatch.setattr(settings_repos, "PlatformSettingsRepository", repo)
    monkeypatch.setattr(settings_repos, "TenantSettingsRepository",   repo)

    # Through the PREVIEW entry point: after the fail-closed change, the
    # enforcement entry point raises on degradation and returns nothing at all,
    # so the "is the result a mixture" question is only observable here.
    policy, _source, _degraded = await resolve_policy_for_preview(
        db=object(), tenant_id="11111111-1111-1111-1111-111111111111",
    )

    assert policy == system_defaults(), (
        f"failing on {fail_key!r} returned a MIXTURE: the layers loaded before "
        "it are present in the result alongside system defaults for the rest. "
        "Which fields belong to the tenant then depends on which read failed, "
        "so the caller cannot reason about the policy it was given."
    )


@pytest.mark.asyncio
async def test_the_tenant_settings_do_apply_when_nothing_fails(monkeypatch):
    """The control. Returning the defaults is only meaningful if the SUCCESS
    path does not -- without this, a resolver that ignored stored settings
    entirely would satisfy every assertion above."""
    import db.repositories.settings as settings_repos

    repo = _repo_failing_on(None)
    monkeypatch.setattr(settings_repos, "PlatformSettingsRepository", repo)
    monkeypatch.setattr(settings_repos, "TenantSettingsRepository",   repo)

    policy, _, degraded = await resolve_policy_for_preview(
        db=object(), tenant_id="11111111-1111-1111-1111-111111111111",
    )
    assert degraded is False

    assert policy["thresholds"]["block"]        == 0.55
    assert policy["detection"]["rule_enabled"]  is False
    assert policy["rate_limit"]["per_minute"]   == 999
    assert policy != system_defaults()
