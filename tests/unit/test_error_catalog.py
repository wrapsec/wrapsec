# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Error Catalog parity, freshness, and envelope guards (Phase 1).

These enforce the LOCKED contract structurally so a change cannot drift:
1. parity   -- every catalog localization key has English text.
2. freshness -- the committed generated map equals a fresh regenerate.
3. no orphans -- no English error/validation key without a matching code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from errors.catalog import (
    ErrorCode,
    ErrorSeverity,
    ValidationCode,
    ERROR_CATALOG,
    VALIDATION_CATALOG,
)
from errors.messages import get_message, render
from scripts.gen_error_catalog import (
    build_generated,
    flatten_locale_en,
    required_keys,
    GENERATED_FILE,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


# -- Guard 1: parity ------------------------------------------------
def test_every_catalog_key_has_english_text():
    flat = flatten_locale_en()
    missing = sorted(k for k in required_keys() if k not in flat)
    assert not missing, f"Catalog keys with no English text in locales/en/: {missing}"


def test_every_error_code_maps_to_its_derived_key():
    for code, meta in ERROR_CATALOG.items():
        assert meta.localization_key == f"errors.{code.value}"


# -- Guard 2: freshness ---------------------------------------------
def test_generated_file_is_fresh():
    committed = json.loads(GENERATED_FILE.read_text(encoding="utf-8"))
    assert committed == build_generated(), (
        "errors/errors_en.generated.json is stale or hand-edited. "
        "Run: python scripts/gen_error_catalog.py"
    )


def test_generated_file_self_labels():
    committed = json.loads(GENERATED_FILE.read_text(encoding="utf-8"))
    assert "__generated__" in committed
    assert committed["__generated__"]["generator"] == "scripts/gen_error_catalog.py"


# -- Guard 3: no orphans --------------------------------------------
def test_no_orphan_error_keys():
    flat = flatten_locale_en()
    catalog_error_keys = {m.localization_key for m in ERROR_CATALOG.values()}
    locale_error_keys  = {k for k in flat if k.startswith("errors.")}
    orphans = sorted(locale_error_keys - catalog_error_keys)
    assert not orphans, f"English error keys with no matching ErrorCode: {orphans}"


def test_no_orphan_validation_keys():
    flat = flatten_locale_en()
    catalog_keys = set(VALIDATION_CATALOG.values())
    locale_keys  = {k for k in flat if k.startswith("forms.errors.")}
    orphans = sorted(locale_keys - catalog_keys)
    assert not orphans, f"English validation keys with no matching ValidationCode: {orphans}"


# -- Metadata sanity ------------------------------------------------
def test_every_error_code_has_catalog_metadata():
    for code in ErrorCode:
        assert code in ERROR_CATALOG, f"{code} missing catalog metadata"


def test_severity_is_error_severity_not_threat_severity():
    for meta in ERROR_CATALOG.values():
        assert meta.severity in (ErrorSeverity.ERROR, ErrorSeverity.WARNING, ErrorSeverity.INFO)


def test_server_faults_are_error_client_conditions_are_warning():
    assert ERROR_CATALOG[ErrorCode.INTERNAL_ERROR].severity is ErrorSeverity.ERROR
    assert ERROR_CATALOG[ErrorCode.DETECTION_ERROR].severity is ErrorSeverity.ERROR
    assert ERROR_CATALOG[ErrorCode.LLM_UNAVAILABLE].severity is ErrorSeverity.ERROR
    assert ERROR_CATALOG[ErrorCode.INVALID_CREDENTIALS].severity is ErrorSeverity.WARNING
    assert ERROR_CATALOG[ErrorCode.CONFLICT].severity is ErrorSeverity.WARNING


# -- Message rendering (ICU simple-arg subset) ----------------------
def test_render_substitutes_named_args():
    assert render("{resource} not found: {identifier}",
                  {"resource": "Department", "identifier": "abc"}) == "Department not found: abc"


def test_render_leaves_unknown_token_verbatim_and_never_raises():
    assert render("{a} and {b}", {"a": "x"}) == "x and {b}"


def test_get_message_known_and_unknown():
    assert get_message("errors.CONFLICT") == "Resource already exists."
    # NOT_FOUND is resource-only per rules section 15 (no identifier in user text).
    assert get_message("errors.NOT_FOUND", {"resource": "Key"}) == "Key not found."
    assert get_message("errors.DOES_NOT_EXIST") is None
