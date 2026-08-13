# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WRAPSEC_FEATURES ceiling + capability resolver (V1 runtime/capability work).

Verifies the plan's feature matrix: unset ceiling = no restriction; a set ceiling
only narrows the registered plugin capabilities; the ceiling can never grant an
unregistered one; unknown feature names fail startup; the raw registry stays
settings-agnostic; and the ceiling never governs proxy/transformer (they are not
configurable capabilities at all).
"""

from __future__ import annotations

import pytest

import services.capabilities as cap
from config.settings import CONFIGURABLE_CAPABILITIES, get_settings


@pytest.fixture
def registry():
    """Isolate the process-wide capability registry per test."""
    saved = set(cap._CAPABILITIES)
    cap._CAPABILITIES.clear()
    yield cap
    cap._CAPABILITIES.clear()
    cap._CAPABILITIES.update(saved)


@pytest.fixture
def set_features(monkeypatch):
    """Set/unset WRAPSEC_FEATURES and refresh the settings cache."""
    def _set(value):
        if value is None:
            monkeypatch.delenv("WRAPSEC_FEATURES", raising=False)
        else:
            monkeypatch.setenv("WRAPSEC_FEATURES", value)
        get_settings.cache_clear()
    yield _set
    get_settings.cache_clear()


# -- feature matrix -------------------------------------------------
def test_unset_ceiling_imposes_no_restriction(registry, set_features):
    registry.register_capability("mcp")
    set_features(None)
    assert registry.capability_available("mcp") is True
    assert registry.effective_capabilities() == ["mcp"]


def test_registered_and_in_ceiling_is_available(registry, set_features):
    registry.register_capability("mcp")
    set_features("mcp")
    assert registry.capability_available("mcp") is True


def test_registered_but_not_in_ceiling_is_unavailable(registry, set_features):
    registry.register_capability("mcp")
    registry.register_capability("rag")   # registered but excluded by the ceiling
    set_features("mcp")
    assert registry.capability_available("rag") is False
    assert registry.effective_capabilities() == ["mcp"]


def test_not_registered_but_in_ceiling_is_unavailable(registry, set_features):
    # Ceiling can never grant a capability that is not registered.
    set_features("mcp")
    assert registry.capability_available("mcp") is False


def test_unknown_feature_name_fails_startup(set_features):
    set_features("proxi")   # typo, not in the static catalog
    with pytest.raises(ValueError):
        get_settings()


def test_empty_features_is_treated_as_unset(registry, set_features):
    registry.register_capability("mcp")
    set_features("   ")
    assert get_settings().configured_features() is None
    assert registry.capability_available("mcp") is True


def test_features_are_normalized(set_features):
    set_features("  MCP , mcp ")
    assert get_settings().configured_features() == frozenset({"mcp"})


# -- raw registry stays pure ----------------------------------------
def test_raw_registry_is_settings_agnostic(registry, set_features):
    registry.register_capability("mcp")
    registry.register_capability("rag")   # registered but excluded by the ceiling
    set_features("mcp")   # valid ceiling (only "mcp" is a configurable name today)
    # is_enabled / get_capabilities ignore the ceiling entirely...
    assert registry.is_enabled("rag") is True
    assert registry.get_capabilities() == ["mcp", "rag"]
    # ...only the resolver applies it.
    assert registry.capability_available("rag") is False


# -- ceiling never governs proxy / transformer / core ---------------
def test_catalog_excludes_non_plugin_layers():
    for name in ("proxy", "transformer", "api", "sdk", "dashboard", "rules", "ml"):
        assert name not in CONFIGURABLE_CAPABILITIES


@pytest.mark.parametrize("name", ["proxy", "transformer", "api"])
def test_non_plugin_names_are_rejected_in_features(set_features, name):
    # WRAPSEC_FEATURES is a plugin ceiling only: proxy/transformer/core names are
    # not configurable and fail validation (a proxy kill switch is never here).
    set_features(name)
    with pytest.raises(ValueError):
        get_settings()
