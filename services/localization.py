# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Locale resolution and validation.

The canonical, framework-independent source of truth for locale SUPPORT is
locales/_meta.json. Its `locales` object maps each supported locale to its
per-locale metadata (currently just text `direction`), so `supported_locales`
is the set of keys -- one place lists locales AND their attributes, extensible
without a schema change. `default_locale` and `catalog_version` sit at the top
level. This module is the backend's reader of that config -- no consumer
maintains its own copy (the frontend reads a generated locale-config.json
derived from the same _meta.json).
See docs/internal/wrapsec_error_handling_localization_rules.md.

Resolution precedence (sec 10) lives here, NOT in any UI framework:

    User -> Tenant -> System default -> English (hardcoded floor)

Backend English-only for now; every stored/configured/requested locale is
validated against the allowlist before use (never trusted blindly).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic_core import PydanticCustomError

_META_PATH = Path(__file__).resolve().parent.parent / "locales" / "_meta.json"

# English is the guaranteed catalog and the ultimate fallback.
FLOOR = "en"

# Text direction is a closed set; every locale entry declares one. LTR is the
# floor default for the English fallback and any unknown lookup.
VALID_DIRECTIONS = ("ltr", "rtl")
DEFAULT_DIRECTION = "ltr"


def _validate_meta(data: dict) -> None:
    """The canonical config invariant, enforced on load (and by the build gate):
    `locales` is a non-empty map whose keys are the supported locales, it
    includes English, every entry declares a valid text direction, and
    default_locale is one of those keys."""
    locales = data.get("locales")
    if not isinstance(locales, dict) or not locales:
        raise ValueError("_meta.json: locales must be a non-empty object")
    lowered = {loc.lower() for loc in locales}
    if FLOOR not in lowered:
        raise ValueError("_meta.json: locales must include 'en'")
    for loc, entry in locales.items():
        if not isinstance(entry, dict):
            raise ValueError(f"_meta.json: locale {loc!r} entry must be an object")
        direction = entry.get("direction")
        if direction not in VALID_DIRECTIONS:
            raise ValueError(
                f"_meta.json: locale {loc!r} direction ({direction!r}) must be "
                f"one of {VALID_DIRECTIONS}"
            )
    default = data.get("default_locale")
    if not default or default.lower() not in lowered:
        raise ValueError(
            f"_meta.json: default_locale ({default!r}) must be one of the "
            f"declared locales ({sorted(locales)})"
        )
    if not data.get("catalog_version"):
        raise ValueError("_meta.json: catalog_version is required")


@lru_cache
def _meta() -> dict:
    with _META_PATH.open(encoding="utf-8") as fh:
        data = json.load(fh)
    _validate_meta(data)
    return data


def supported_locales() -> list[str]:
    return list(_meta()["locales"].keys())


def default_locale() -> str:
    return _meta()["default_locale"]


def catalog_version() -> str:
    return _meta()["catalog_version"]


def locale_directions() -> dict[str, str]:
    """Map of every supported locale to its text direction ('ltr' | 'rtl')."""
    return {loc: entry["direction"] for loc, entry in _meta()["locales"].items()}


def locale_direction(locale: str | None) -> str:
    """Text direction for `locale` (allowlist-canonicalized), or the LTR floor
    when it is empty/unsupported. The render surface (html dir) uses this; it
    never trusts a raw value that is not in the allowlist."""
    canonical = canonical_locale(locale, supported_locales())
    if canonical is None:
        return DEFAULT_DIRECTION
    return locale_directions().get(canonical, DEFAULT_DIRECTION)


def canonical_locale(value: str | None, supported: list[str]) -> str | None:
    """
    Return the allowlist's canonical spelling of `value` (case-insensitive
    match), or None if it is empty or not supported. Exact allowlist membership
    is the security boundary -- an arbitrary or path-like string simply fails to
    match and is rejected.
    """
    if not value:
        return None
    lowered = value.strip().lower()
    if not lowered:
        return None
    for loc in supported:
        if loc.lower() == lowered:
            return loc
    return None


def resolve_locale(
    user_locale:   str | None,
    tenant_locale: str | None,
    *,
    supported: list[str] | None = None,
    default:   str | None       = None,
) -> str:
    """Effective locale: first supported value in User -> Tenant -> System -> en.
    `supported`/`default` default to the canonical _meta.json config (overridable
    in tests)."""
    supported = supported if supported is not None else supported_locales()
    default   = default   if default   is not None else default_locale()
    for candidate in (user_locale, tenant_locale, default):
        canonical = canonical_locale(candidate, supported)
        if canonical is not None:
            return canonical
    return FLOOR


def validate_locale_input(
    value: str | None,
    *,
    supported: list[str] | None = None,
) -> str | None:
    """
    Validate an explicitly-set locale (PATCH /me, PUT /tenant). None is allowed
    (clears the preference -> inherit). An unsupported value raises a
    PydanticCustomError typed `invalid_locale`, which the error handler maps to
    a 422 INVALID_ENUM with the allowed set (see errors/catalog.py).
    """
    if value is None:
        return None
    supported = supported if supported is not None else supported_locales()
    canonical = canonical_locale(value, supported)
    if canonical is None:
        raise PydanticCustomError(
            "invalid_locale",
            "unsupported locale",
            {"expected": ", ".join(repr(loc) for loc in supported)},
        )
    return canonical
