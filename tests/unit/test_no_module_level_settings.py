# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
F-6 regression: hot-path modules must not capture settings at import time.

CLAUDE.md documents the invariant:
    get_settings() per-call, never at module level. Settings are reloaded on
    each call to support key rotation and test isolation.

Prior regression: three hot-path modules held a module-level `settings`:
    - engine/detection/llm_detector.py (dead capture; never read)
    - services/policy_resolver.py      (used inside resolve_policy for
                                        secret_key and threshold fallback)
    - api/v1/endpoints/ai.py           (used inside ai_request for trial and
                                        debug limits)

Test isolation was silently broken: pytest overrides of block_threshold /
sanitize_threshold via env didn't reach these modules once imported. A key
rotation of SECRET_KEY had no effect on policy_resolver.decrypt() until the
whole process was restarted.

This test greps the top-level module namespace to assert none of the three
files re-introduce a module-level `settings` attribute. It is intentionally
narrow - it does NOT check every module in the tree, only the three that
regressed - so unrelated future imports are not blocked.
"""

import importlib


def _has_module_level_settings(module_path: str) -> bool:
    """
    Import the module and check whether it exposes a top-level attribute
    named `settings` that is not itself a submodule or None.
    """
    mod = importlib.import_module(module_path)
    if not hasattr(mod, "settings"):
        return False
    val = mod.settings
    # A submodule (config.settings) is fine; we only care about a captured
    # Settings instance shared across the whole process.
    import types
    if isinstance(val, types.ModuleType):
        return False
    return val is not None


def test_llm_detector_has_no_module_level_settings():
    """
    engine.detection.llm_detector previously captured `settings = get_settings()`
    at import - a dead capture (never read). Regressing this reintroduces the
    stale-config surface.
    """
    assert not _has_module_level_settings("engine.detection.llm_detector"), (
        "engine.detection.llm_detector must not hold a module-level Settings "
        "instance - use get_settings() per call. See F-6."
    )


def test_policy_resolver_has_no_module_level_settings():
    """
    services.policy_resolver previously captured `settings = get_settings()`
    at import. resolve_policy() uses secret_key for decrypt and threshold
    values as fallbacks - a stale capture defeats key rotation and test
    threshold overrides.
    """
    assert not _has_module_level_settings("services.policy_resolver"), (
        "services.policy_resolver must not hold a module-level Settings "
        "instance - resolve_policy() calls get_settings() per invocation. "
        "See F-6."
    )


def test_ai_endpoint_has_no_module_level_settings():
    """
    api.v1.endpoints.ai previously captured `settings = get_settings()` at
    import. ai_request() reads trial_max_input_chars, trial_rate_limit and
    debug_rate_limit per request - a stale capture broke test isolation for
    these fields.
    """
    assert not _has_module_level_settings("api.v1.endpoints.ai"), (
        "api.v1.endpoints.ai must not hold a module-level Settings instance - "
        "ai_request() calls get_settings() per invocation. See F-6."
    )
