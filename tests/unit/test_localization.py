# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Locale resolution + validation (Phase 2/3).

Covers the User -> Tenant -> System -> English precedence, allowlist matching,
explicit-setter rejection, and the canonical _meta.json config invariant
(locales map non-empty, includes en, each entry declares a valid direction,
default is one of the locales, catalog_version set).
"""

import pytest
from pydantic_core import PydanticCustomError

from services.localization import (
    _validate_meta,
    canonical_locale,
    locale_direction,
    resolve_locale,
    validate_locale_input,
)


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
    kw = dict(supported=["en", "de"], default="de")
    assert resolve_locale("en", "de", **kw) == "en"   # user wins
    assert resolve_locale(None, "de", **kw) == "de"   # tenant
    assert resolve_locale(None, None, **kw) == "de"   # system default


def test_resolve_skips_invalid_candidates():
    kw = dict(supported=["en", "de"], default="de")
    assert resolve_locale("xx", "de", **kw) == "de"   # bad user -> tenant
    assert resolve_locale("xx", "yy", **kw) == "de"   # both bad -> system


def test_resolve_floor_is_english():
    # de is not supported here, so a de preference is ignored and the system
    # default en applies; the hardcoded floor also returns en.
    assert resolve_locale("de", "de", supported=["en"], default="en") == "en"


# -- validate_locale_input (explicit setters) -----------------------
def test_validate_accepts_supported_and_none():
    assert validate_locale_input(None, supported=["en"]) is None
    assert validate_locale_input("en", supported=["en"]) == "en"
    assert validate_locale_input("EN", supported=["en"]) == "en"


def test_validate_rejects_unsupported_as_invalid_locale():
    with pytest.raises(PydanticCustomError) as exc:
        validate_locale_input("de", supported=["en"])
    # Maps to 422 INVALID_ENUM via errors.catalog.PYDANTIC_TYPE_TO_VALIDATION.
    assert exc.value.type == "invalid_locale"


# -- canonical _meta.json config invariant --------------------------
def test_meta_valid_config_passes():
    _validate_meta({
        "locales": {"en": {"direction": "ltr", "label": "English"}},
        "default_locale": "en",
        "catalog_version": "1.0.0",
    })
    _validate_meta({
        "locales": {
            "en": {"direction": "ltr", "label": "English"},
            "ar": {"direction": "rtl", "label": "العربية"},
        },
        "default_locale": "ar",
        "catalog_version": "1.0.0",
    })


def test_meta_rejects_default_outside_allowlist():
    with pytest.raises(ValueError, match="default_locale"):
        _validate_meta({
            "locales": {"en": {"direction": "ltr", "label": "English"}},
            "default_locale": "de",
            "catalog_version": "1.0.0",
        })


def test_meta_requires_english_nonempty_and_version():
    with pytest.raises(ValueError, match="must include 'en'"):
        _validate_meta({
            "locales": {"de": {"direction": "ltr", "label": "Deutsch"}},
            "default_locale": "de",
            "catalog_version": "1.0.0",
        })
    with pytest.raises(ValueError, match="non-empty object"):
        _validate_meta({"locales": {}, "default_locale": "en", "catalog_version": "1.0.0"})
    with pytest.raises(ValueError, match="catalog_version"):
        _validate_meta({
            "locales": {"en": {"direction": "ltr", "label": "English"}},
            "default_locale": "en",
        })


def test_meta_rejects_invalid_or_missing_direction():
    with pytest.raises(ValueError, match="direction"):
        _validate_meta({
            "locales": {"en": {"direction": "sideways", "label": "English"}},
            "default_locale": "en",
            "catalog_version": "1.0.0",
        })
    with pytest.raises(ValueError, match="direction"):
        _validate_meta({
            "locales": {"en": {"label": "English"}},
            "default_locale": "en",
            "catalog_version": "1.0.0",
        })


def test_meta_requires_nonempty_label():
    with pytest.raises(ValueError, match="label"):
        _validate_meta({
            "locales": {"en": {"direction": "ltr"}},
            "default_locale": "en",
            "catalog_version": "1.0.0",
        })
    with pytest.raises(ValueError, match="label"):
        _validate_meta({
            "locales": {"en": {"direction": "ltr", "label": "  "}},
            "default_locale": "en",
            "catalog_version": "1.0.0",
        })


# -- locale_direction (render-surface lookup) -----------------------
def test_locale_direction_uses_meta_and_ltr_floor():
    # Real _meta.json ships en=ltr; an unsupported/empty value falls to the floor.
    assert locale_direction("en") == "ltr"
    assert locale_direction("EN") == "ltr"
    assert locale_direction(None) == "ltr"
    assert locale_direction("xx") == "ltr"
