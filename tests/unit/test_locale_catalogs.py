# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Locale catalog validation, generation, and freshness guards.

Enforces the pipeline contract structurally so it cannot drift:
- parity   -- every catalog localization key has English text (backend map)
- freshness -- every committed generated artifact equals a fresh regenerate
- no orphans -- no English error/validation key without a matching code
- namespaces -- every locale provides the required domain namespaces
- config    -- catalog_version is consistent across canonical + generated
- ICU       -- structural validation runs during generation
"""

from __future__ import annotations

import json
import re

import pytest

from errors.catalog import (
    ERROR_CATALOG,
    VALIDATION_CATALOG,
)
from errors.messages import get_message, render
from scripts.gen_locale_catalogs import (
    BACKEND_MAP,
    DASH_CONFIG,
    DASH_MESSAGES,
    REQUIRED_NAMESPACES,
    _flatten_locale,
    _icu_structural_check,
    build_backend_map,
    build_dashboard_messages,
    build_locale_config,
    load_meta,
)


# -- Guard 1: parity ------------------------------------------------
def test_every_catalog_key_has_english_text():
    flat = _flatten_locale("en")
    required = {m.localization_key for m in ERROR_CATALOG.values()}
    required.update(VALIDATION_CATALOG.values())
    missing = sorted(k for k in required if k not in flat)
    assert not missing, f"Catalog keys with no English text: {missing}"


def test_every_error_code_maps_to_its_derived_key():
    for code, meta in ERROR_CATALOG.items():
        assert meta.localization_key == f"errors.{code.value}"


# -- Guard 2: freshness (every generated artifact) ------------------
def test_backend_map_is_fresh():
    committed = json.loads(BACKEND_MAP.read_text(encoding="utf-8"))
    assert committed == build_backend_map(), (
        "errors/errors_en.generated.json is stale/hand-edited. "
        "Run: python scripts/gen_locale_catalogs.py"
    )


def test_dashboard_messages_are_fresh():
    built = build_dashboard_messages()
    for locale, namespaces in built.items():
        path = DASH_MESSAGES / f"{locale}.json"
        assert path.exists(), f"missing generated {path}"
        assert json.loads(path.read_text(encoding="utf-8")) == namespaces, (
            f"dashboard/messages/{locale}.json is stale. "
            "Run: python scripts/gen_locale_catalogs.py"
        )


def test_locale_config_is_fresh():
    committed = json.loads(DASH_CONFIG.read_text(encoding="utf-8"))
    assert committed == build_locale_config()


# -- Guard 3: no orphans --------------------------------------------
def test_no_orphan_error_keys():
    flat = _flatten_locale("en")
    catalog_error_keys = {m.localization_key for m in ERROR_CATALOG.values()}
    locale_error_keys  = {k for k in flat if k.startswith("errors.")}
    orphans = sorted(locale_error_keys - catalog_error_keys)
    assert not orphans, f"English error keys with no matching ErrorCode: {orphans}"


def test_no_orphan_validation_keys():
    flat = _flatten_locale("en")
    catalog_keys = set(VALIDATION_CATALOG.values())
    locale_keys  = {k for k in flat if k.startswith("forms.errors.")}
    orphans = sorted(locale_keys - catalog_keys)
    assert not orphans, f"English validation keys with no matching ValidationCode: {orphans}"


# -- Guard 4: required namespaces exist for every supported locale --
def test_every_supported_locale_has_required_namespaces():
    meta = load_meta()
    for locale in meta["locales"]:
        namespaces = build_dashboard_messages()[locale]
        for ns in REQUIRED_NAMESPACES:
            assert ns in namespaces, f"locale {locale} missing namespace {ns}"


# -- Guard 7: text direction is emitted for every supported locale --
def test_locale_config_directions_cover_every_locale():
    config    = build_locale_config()
    supported = set(config["supported_locales"])
    dirs      = config["directions"]
    assert set(dirs) == supported, "directions must cover exactly the supported locales"
    assert all(d in ("ltr", "rtl") for d in dirs.values()), "direction must be ltr|rtl"
    assert dirs["en"] == "ltr", "English is left-to-right"


# -- Guard 8: translation lockstep (non-default locales vs the fallback base) ---
# The fallback base is default_locale: a key missing from another locale resolves
# to it (i18n/request.ts deepMerge), so a NON-default locale is a valid override
# layer only if it introduces no keys the base lacks and, for every shared key,
# uses the SAME ICU arguments and rich-text tags. next build validates ICU syntax
# but NOT these -- an extra {arg} throws MISSING_VALUE and a dropped <tag> breaks
# t.rich, both only when that locale actually renders. Missing keys are allowed
# (the fallback covers them), so this never requires a full translation.
def _icu_arg_names(text: str) -> set[str]:
    """Top-level ICU argument names ({name} or {name, type, ...}). Nested args in
    plural/select branches are intentionally ignored -- top-level parity is the
    call-site contract."""
    names: set[str] = set()
    depth = 0
    buf = ""
    for ch in text:
        if ch == "{":
            if depth == 0:
                buf = ""
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                m = re.match(r"\s*([A-Za-z0-9_]+)", buf)
                if m:
                    names.add(m.group(1))
        elif depth == 1:
            buf += ch
    return names


def _tag_names(text: str) -> list[str]:
    """Rich-text tag tokens (<link>, <b>, <code>, <br>, and their closers) as a
    sorted multiset; t.rich needs a matching set across locales."""
    return sorted(re.findall(r"</?([A-Za-z0-9]+)\s*>", text))


def test_non_default_locales_are_valid_override_layers():
    meta    = load_meta()
    default = meta["default_locale"]
    base    = _flatten_locale(default)
    others  = [loc for loc in meta["locales"] if loc != default]

    for loc in others:
        flat = _flatten_locale(loc)

        orphans = sorted(set(flat) - set(base))
        assert not orphans, (
            f"[{loc}] has keys absent from the '{default}' base (typo/dead, never "
            f"rendered): {orphans}"
        )

        arg_diffs = {
            key: (sorted(_icu_arg_names(base[key])), sorted(_icu_arg_names(flat[key])))
            for key in set(flat) & set(base)
            if _icu_arg_names(flat[key]) != _icu_arg_names(base[key])
        }
        assert not arg_diffs, (
            f"[{loc}] ICU argument sets differ from '{default}' (extra arg -> "
            f"runtime MISSING_VALUE, dropped arg -> missing content) "
            f"{{key: (base, {loc})}}: {arg_diffs}"
        )

        tag_diffs = {
            key: (_tag_names(base[key]), _tag_names(flat[key]))
            for key in set(flat) & set(base)
            if _tag_names(flat[key]) != _tag_names(base[key])
        }
        assert not tag_diffs, (
            f"[{loc}] rich-text tags differ from '{default}' (t.rich needs a "
            f"matching tag set) {{key: (base, {loc})}}: {tag_diffs}"
        )


# -- Guard 5: catalog_version consistency (build contract) ----------
def test_catalog_version_consistent_across_artifacts():
    version = load_meta()["catalog_version"]
    assert build_backend_map()["__generated__"]["catalog_version"] == version
    assert build_locale_config()["catalog_version"] == version
    committed_backend = json.loads(BACKEND_MAP.read_text(encoding="utf-8"))
    committed_config  = json.loads(DASH_CONFIG.read_text(encoding="utf-8"))
    assert committed_backend["__generated__"]["catalog_version"] == version
    assert committed_config["catalog_version"] == version


# -- Guard 6: ICU structural validation -----------------------------
def test_icu_structural_check_accepts_balanced_and_rejects_unbalanced():
    _icu_structural_check("ok", "{resource} not found.")           # balanced
    _icu_structural_check("plain", "no args here")                 # none
    with pytest.raises(SystemExit):
        _icu_structural_check("bad", "{resource not found")        # unbalanced open
    with pytest.raises(SystemExit):
        _icu_structural_check("bad2", "resource} not found")       # unbalanced close


# -- Message rendering (ICU simple-arg subset) ----------------------
def test_render_substitutes_named_args():
    assert render("{resource} not found.", {"resource": "Department"}) == "Department not found."


def test_get_message_known_and_unknown():
    assert get_message("errors.CONFLICT") == "Resource already exists."
    assert get_message("errors.NOT_FOUND", {"resource": "Key"}) == "Key not found."
    assert get_message("errors.DOES_NOT_EXIST") is None
