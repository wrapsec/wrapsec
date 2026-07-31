# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.capabilities.

The capability registry and the entry-point plugin loader are the single seam
between the OSS core and the private enterprise package. Tests cover the
registry, the OSS no-op path (no plugins installed), a discovered plugin being
loaded via a fake entry point, and the fail-soft behavior when one plugin
raises.
"""

from __future__ import annotations

import pytest

import services.capabilities as cap


@pytest.fixture(autouse=True)
def _clean_registry():
    cap._CAPABILITIES.clear()
    yield
    cap._CAPABILITIES.clear()


class _FakeEP:
    def __init__(self, name, register):
        self.name = name
        self._register = register

    def load(self):
        return self._register


# --- registry ---------------------------------------------------------

def test_register_query_and_sorted_output():
    assert cap.get_capabilities() == []
    cap.register_capability("sso")
    cap.register_capability("compliance")
    cap.register_capability("sso")           # idempotent
    assert cap.get_capabilities() == ["compliance", "sso"]
    assert cap.is_enabled("sso") is True
    assert cap.is_enabled("nope") is False


# --- loader -----------------------------------------------------------

def test_load_plugins_is_noop_in_oss(monkeypatch):
    monkeypatch.setattr(cap, "entry_points", lambda group=None: [])
    cap.load_plugins(object())               # must not raise
    assert cap.get_capabilities() == []


def test_load_plugins_discovers_and_registers(monkeypatch):
    seen = {}

    def _register(app):
        seen["app"] = app
        cap.register_capability("sso")

    monkeypatch.setattr(cap, "entry_points",
                        lambda group=None: [_FakeEP("enterprise", _register)])
    sentinel = object()
    cap.load_plugins(sentinel)

    assert seen["app"] is sentinel           # app is passed through to register()
    assert cap.is_enabled("sso")


def test_load_plugins_tolerates_a_failing_plugin(monkeypatch):
    def _bad(app):
        raise RuntimeError("boom")

    def _good(app):
        cap.register_capability("ok")

    monkeypatch.setattr(cap, "entry_points",
                        lambda group=None: [_FakeEP("bad", _bad), _FakeEP("good", _good)])

    cap.load_plugins(object())               # must not raise despite the bad plugin
    assert cap.is_enabled("ok")              # the healthy plugin still loaded


def test_plugin_group_is_the_documented_name():
    # Renaming this would break every installed plugin -- pin it.
    assert cap.PLUGIN_GROUP == "wrapsec.plugins"
