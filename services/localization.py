# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Locale resolution and validation.

The canonical, framework-independent source of truth for locale SUPPORT is
locales/_meta.json (supported_locales, default_locale, catalog_version). This
module is the backend's reader of that config -- no consumer maintains its own
copy (the frontend reads a generated locale-config.json derived from the same
_meta.json). See docs/internal/wrapsec_error_handling_localization_rules.md.

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


def _validate_meta(data: dict) -> None:
    """The canonical config invariant, enforced on load (and by the build gate):
    supported_locales is non-empty, includes English, and the default is one of
    the supported locales."""
    supported = data.get("supported_locales") or []
    default   = data.get("default_locale")
    if not supported:
        raise ValueError("_meta.json: supported_locales must not be empty")
    lowered = [loc.lower() for loc in supported]
    if FLOOR not in lowered:
        raise ValueError("_meta.json: supported_locales must include 'en'")
    if not default or default.lower() not in lowered:
        raise ValueError(
            f"_meta.json: default_locale ({default!r}) must be one of "
            f"supported_locales ({supported})"
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
    return list(_meta()["supported_locales"])


def default_locale() -> str:
    return _meta()["default_locale"]


def catalog_version() -> str:
    return _meta()["catalog_version"]


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
