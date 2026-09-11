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

import pytest


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


# ---------------------------------------------------------------------------
# Tree-wide fence
# ---------------------------------------------------------------------------
#
# The three tests above check for a module-level attribute literally NAMED
# `settings`. That is how the original regression looked, and it is why the
# next one was invisible: `_auth_settings = get_settings()` in
# services/auth/service.py, and two database engines built at import from
# `get_settings().database_url`, were all missed. Nothing was named `settings`,
# and an Engine is not a Settings instance to begin with.
#
# What actually matters is not the NAME but the MOMENT: anything DERIVED from
# settings at import time freezes configuration before a caller can influence
# it. Import happens at collection time, so a test that points the database
# elsewhere and clears the settings cache still wrote to the original URL --
# silently, because the write succeeds either way.
#
# This walks the production tree for module-level assignments whose value
# contains a get_settings() call, whatever the target is called.

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

_PRODUCTION_DIRS = (
    "api", "services", "engine", "db", "cache", "workers", "security",
    "clients", "errors", "domain", "observability", "mcp_server",
    "interfaces", "config",
)

# Import-time capture is CORRECT at these two sites. Both build a process
# singleton whose constructor argument has no per-call form, and neither is
# re-read afterwards to make a decision.
#
#   api/main.py      the FastAPI app object is constructed once, at import, and
#                    title/version/docs URLs are constructor arguments. There is
#                    no later moment at which to read them.
#   db/session.py    the async engine IS the process-wide connection pool. Its
#                    session factory is imported by name at 22 sites and must be
#                    one object; building it per call would build a pool per call.
#
# A new entry here needs the same argument: a true singleton, not merely
# something convenient to hoist.
_JUSTIFIED_IMPORT_TIME_CAPTURE = {
    "api/main.py",
    "db/session.py",
}


def _import_time_captures() -> list[str]:
    found = []
    for directory in _PRODUCTION_DIRS:
        for path in sorted((_ROOT / directory).rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            if rel in _JUSTIFIED_IMPORT_TIME_CAPTURE:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
            except SyntaxError:
                continue
            for node in tree.body:                       # module level only
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                for sub in ast.walk(node):
                    if (isinstance(sub, ast.Call)
                            and isinstance(sub.func, ast.Name)
                            and sub.func.id.endswith("get_settings")):
                        target = (node.targets[0] if isinstance(node, ast.Assign)
                                  else node.target)
                        found.append(f"{rel}:{node.lineno} {ast.unparse(target)}")
                        break
    return found


def test_no_module_level_settings_derived_state_anywhere():
    """No production module may derive import-time state from get_settings().

    Covers the shape the name-based tests cannot see: a differently-named
    binding, or an object BUILT from settings (an engine, a client, a
    sessionmaker) rather than the settings object itself.
    """
    captures = _import_time_captures()
    assert not captures, (
        "module-level state derived from get_settings() at import:\n  "
        + "\n  ".join(captures)
        + "\n\nBuild it on first use instead (see _auth_event_sf in "
          "services/auth/service.py), or add the file to "
          "_JUSTIFIED_IMPORT_TIME_CAPTURE with the reason it is a true singleton."
    )


def test_the_allowlist_only_names_files_that_still_capture():
    """An allowlist entry that no longer captures is a stale exemption.

    Left behind, it silently re-permits the pattern in a file that had been
    cleaned up.
    """
    for rel in sorted(_JUSTIFIED_IMPORT_TIME_CAPTURE):
        tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"), filename=rel)
        captures = [
            node for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and any(isinstance(s, ast.Call) and isinstance(s.func, ast.Name)
                    and s.func.id.endswith("get_settings")
                    for s in ast.walk(node))
        ]
        assert captures, (
            f"{rel} is exempted from the import-time-capture fence but no longer "
            f"captures settings at import; remove it from the allowlist"
        )


def test_auth_event_engines_are_not_built_at_import():
    """The two auth-event session factories must be callables, not objects.

    They wrote every authentication event -- logins, lockouts, token reuse --
    and each captured the database URL at import. Under a test that redirects
    the database, the events went to the original one and the assertion looked
    for them in the new one.
    """
    import importlib

    for module_path in ("services.auth.service", "api.v1.middleware.auth"):
        module = importlib.import_module(module_path)
        assert not hasattr(module, "_auth_event_engine"), (
            f"{module_path} builds an engine at import again"
        )
        factory = module._auth_event_sf
        assert callable(factory), f"{module_path}._auth_event_sf must be a factory"
        assert hasattr(factory, "cache_clear"), (
            f"{module_path}._auth_event_sf should be cached so the pool is reused, "
            f"and clearable so a test can drop it"
        )


def test_drop_tables_guard_reads_the_environment_live():
    """The production guard on drop_tables() must not consult a stale capture.

    db/session.py captures settings at import to build the engine -- which is
    legitimate, the pool is a singleton -- but the guard in front of
    `drop_tables()` was reading `environment` from that same capture. The
    capture predates any configuration applied afterwards, and it survives
    `get_settings.cache_clear()`.

    So the sequence below -- mark the environment production, clear the cache,
    call the guarded function -- consulted a value frozen before the first line
    of the test ran. The guard is the last thing standing in front of dropping
    every table; it has to answer about the environment the process is in NOW.
    """
    import os

    from config.settings import get_settings

    original = os.environ.get("ENVIRONMENT")
    try:
        os.environ["ENVIRONMENT"] = "production"
        get_settings.cache_clear()

        import asyncio

        from db.session import drop_tables

        with pytest.raises(RuntimeError, match="never be called in production"):
            asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
                drop_tables()
            )
    finally:
        if original is None:
            os.environ.pop("ENVIRONMENT", None)
        else:
            os.environ["ENVIRONMENT"] = original
        get_settings.cache_clear()
