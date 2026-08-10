# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Locale resolution + validation (Phase 2).

Covers the User -> Tenant -> System -> English precedence, allowlist matching,
explicit-setter rejection, and the startup invariant that system_default_locale
must be a supported locale.
"""

from types import SimpleNamespace

import pytest
from pydantic_core import PydanticCustomError

from config.settings import Settings
from services.localization import (
    canonical_locale,
    resolve_locale,
    validate_locale_input,
)


def _s(supported, default="en"):
    return SimpleNamespace(supported_locales=supported, system_default_locale=default)


# -- canonical_locale (allowlist is the security boundary) ----------
def test_canonical_is_case_insensitive_and_trimmed():
    assert canonical_locale("EN", ["en"]) == "en"
    assert canonical_locale("  en  ", ["en"]) == "en"
    assert canonical_locale("de", ["en", "de"]) == "de"


def test_canonical_rejects_empty_none_and_unsupported():
    assert canonical_locale(None, ["en"]) is None
    assert canonical_locale("", ["en"]) is None
    assert canonical_locale("   ", ["en"]) is None
    assert canonical_locale("de", ["en"]) is None
    assert canonical_locale("../../etc/passwd", ["en"]) is None


# -- resolve_locale precedence --------------------------------------
def test_resolve_prefers_user_then_tenant_then_system():
    s = _s(["en", "de"], default="de")
    assert resolve_locale("en", "de", settings=s) == "en"   # user wins
    assert resolve_locale(None, "de", settings=s) == "de"   # tenant
    assert resolve_locale(None, None, settings=s) == "de"   # system default


def test_resolve_skips_invalid_candidates():
    s = _s(["en", "de"], default="de")
    assert resolve_locale("xx", "de", settings=s) == "de"   # bad user -> tenant
    assert resolve_locale("xx", "yy", settings=s) == "de"   # both bad -> system


def test_resolve_floor_is_english():
    # de is not supported here, so a de preference is ignored and the system
    # default en applies; the hardcoded floor also returns en.
    s = _s(["en"], default="en")
    assert resolve_locale("de", "de", settings=s) == "en"


# -- validate_locale_input (explicit setters) -----------------------
def test_validate_accepts_supported_and_none():
    s = _s(["en"])
    assert validate_locale_input(None, settings=s) is None
    assert validate_locale_input("en", settings=s) == "en"
    assert validate_locale_input("EN", settings=s) == "en"


def test_validate_rejects_unsupported_as_invalid_locale():
    s = _s(["en"])
    with pytest.raises(PydanticCustomError) as exc:
        validate_locale_input("de", settings=s)
    # Maps to 422 INVALID_ENUM via errors.catalog.PYDANTIC_TYPE_TO_VALIDATION.
    assert exc.value.type == "invalid_locale"


# -- startup invariant: system default must be supported ------------
def test_valid_config_passes():
    Settings.validate_locale_config(_s(["en"], "en"))
    Settings.validate_locale_config(_s(["en", "de"], "de"))


def test_config_rejects_default_outside_allowlist():
    with pytest.raises(ValueError, match="system_default_locale"):
        Settings.validate_locale_config(_s(["en"], "de"))


def test_config_requires_english_and_nonempty():
    with pytest.raises(ValueError, match="must include 'en'"):
        Settings.validate_locale_config(_s(["de"], "de"))
    with pytest.raises(ValueError, match="must not be empty"):
        Settings.validate_locale_config(_s([], "en"))
