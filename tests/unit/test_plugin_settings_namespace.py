# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Plugin settings/entitlement namespace helpers (Phase 2, 2.11). The write-path
enforcement (core refuses the reserved prefix; a plugin opts in) is proven end to
end in tests/integration/test_refplugin.py::test_plugin_settings_namespace_seam.
"""
import pytest

from db.repositories.settings import (
    PLUGIN_KEY_PREFIX,
    is_plugin_settings_key,
    plugin_settings_key,
)


def test_prefix_is_stable():
    assert PLUGIN_KEY_PREFIX == "plugin:"


def test_is_plugin_settings_key():
    assert is_plugin_settings_key("plugin:billing:entitlement") is True
    assert is_plugin_settings_key("policy_thresholds") is False
    assert is_plugin_settings_key("") is False


def test_plugin_settings_key_builds_three_part_name():
    assert plugin_settings_key("billing", "entitlement") == "plugin:billing:entitlement"
    assert is_plugin_settings_key(plugin_settings_key("x", "y")) is True


@pytest.mark.parametrize("name, key", [
    ("", "k"),               # empty name
    ("has:colon", "k"),      # name would break the three-part structure
    ("billing", ""),         # empty key
])
def test_plugin_settings_key_rejects_malformed(name, key):
    with pytest.raises(ValueError):
        plugin_settings_key(name, key)
