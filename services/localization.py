# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Locale resolution and validation.

Backend English-only for now: this module establishes the preference + resolution
infrastructure (the dashboard consumes the resolved locale in a later phase). It
never trusts a stored or configured locale blindly -- every candidate is
validated against the supported-locales allowlist before use.

Precedence (docs/internal/wrapsec_error_handling_localization_rules.md, sec 10):

    User -> Tenant -> System default -> English (hardcoded floor)
"""

from __future__ import annotations

from pydantic_core import PydanticCustomError

from config.settings import get_settings

# English is the guaranteed catalog and the ultimate fallback. The settings
# validator enforces that this is always a member of supported_locales.
FLOOR = "en"


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
    settings=None,
) -> str:
    """Effective locale: first supported value in User -> Tenant -> System -> en."""
    s         = settings or get_settings()
    supported = s.supported_locales
    for candidate in (user_locale, tenant_locale, s.system_default_locale):
        canonical = canonical_locale(candidate, supported)
        if canonical is not None:
            return canonical
    return FLOOR


def validate_locale_input(value: str | None, settings=None) -> str | None:
    """
    Validate an explicitly-set locale (PATCH /me, PUT /tenant). None is allowed
    (clears the preference -> inherit). An unsupported value raises a
    PydanticCustomError typed `invalid_locale`, which the error handler maps to
    a 422 INVALID_ENUM with the allowed set (see errors/catalog.py).
    """
    if value is None:
        return None
    s         = get_settings() if settings is None else settings
    canonical = canonical_locale(value, s.supported_locales)
    if canonical is None:
        raise PydanticCustomError(
            "invalid_locale",
            "unsupported locale",
            {"expected": ", ".join(repr(loc) for loc in s.supported_locales)},
        )
    return canonical
