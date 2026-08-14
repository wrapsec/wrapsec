# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Reference-plugin seam validation (increment 1).

Each test answers one strategy question from docs/internal/saas_plugin_strategy.md
section 6. Together they prove -- by construction -- that the open-core plugin
model works, and they lock in the two findings the exercise surfaced.

The plugin is loaded onto the REAL app (full middleware stack) and removed after
each test, so the OSS-edition "absent" behavior stays observable and nothing
leaks into the wider suite.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_REFPLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "refplugin"
if str(_REFPLUGIN) not in sys.path:
    sys.path.insert(0, str(_REFPLUGIN))

import wrapsec_refplugin


@pytest.fixture
def refplugin_app():
    """Load refplugin onto the real app, then restore routes + capabilities."""
    import services.capabilities as caps
    from api.main import app

    routes_before = list(app.router.routes)
    caps_before   = set(caps._CAPABILITIES)
    wrapsec_refplugin.register(app)
    try:
        yield app
    finally:
        app.router.routes[:] = routes_before
        caps._CAPABILITIES.clear()
        caps._CAPABILITIES.update(caps_before)


# ── Discovery / registration ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_plugin_absent_route_404_and_caps_empty(client, admin_headers):
    """OSS edition: no plugin -> no plugin surface, capability set empty of it."""
    r = await client.get("/v1/ref/ping", headers=admin_headers)
    assert r.status_code == 404
    caps = (await client.get("/v1/capabilities", headers=admin_headers)).json()["capabilities"]
    assert "ref.ping" not in caps


@pytest.mark.asyncio
async def test_load_plugins_discovers_and_registers(client, admin_headers):
    """Full discovery path: load_plugins finds the entry point, calls register,
    the capability becomes effective and the route is live."""
    import services.capabilities as caps
    from api.main import app

    routes_before = list(app.router.routes)
    caps_before   = set(caps._CAPABILITIES)
    ep = MagicMock()
    ep.name = "refplugin"
    ep.load = MagicMock(return_value=wrapsec_refplugin.register)
    try:
        with patch("services.capabilities.entry_points", return_value=[ep]):
            caps.load_plugins(app)
        listed = (await client.get("/v1/capabilities", headers=admin_headers)).json()["capabilities"]
        assert "ref.ping" in listed
        r = await client.get("/v1/ref/ping", headers=admin_headers)
        assert r.status_code == 200
        assert r.json()["pong"] is True
    finally:
        app.router.routes[:] = routes_before
        caps._CAPABILITIES.clear()
        caps._CAPABILITIES.update(caps_before)


# ── The critical security property: plugin routes go through auth ────────────

@pytest.mark.asyncio
async def test_plugin_route_requires_auth(client, refplugin_app):
    """THE property: a plugin-mounted route is protected by default. AuthMiddleware
    is allowlist-based (PUBLIC_PATHS), so /v1/ref/ping is NOT public -- no creds
    must yield 401, not an unauthenticated surface."""
    r = await client.get("/v1/ref/ping")   # no credentials
    assert r.status_code == 401


# ── Capability ceiling + self-gating cardinal rule ──────────────────────────

@pytest.mark.asyncio
async def test_capability_ceiling_hides_and_route_self_gates(client, admin_headers, refplugin_app, monkeypatch):
    """WRAPSEC_FEATURES ceiling excludes ref.ping: capability disappears from
    /v1/capabilities, and the authenticated route self-gates to 404 (the
    capability is informational; the route enforces)."""
    from config.settings import get_settings

    # A ceiling that permits some OTHER (known) capability but not ref.ping. Must
    # be a name the ceiling validator accepts -- see the finding test below: the
    # valid set is hardcoded and does not include plugin capabilities.
    monkeypatch.setenv("WRAPSEC_FEATURES", "mcp")
    get_settings.cache_clear()
    try:
        caps = (await client.get("/v1/capabilities", headers=admin_headers)).json()["capabilities"]
        assert "ref.ping" not in caps                      # hidden by the ceiling
        r = await client.get("/v1/ref/ping", headers=admin_headers)
        assert r.status_code == 404                         # route self-gates
    finally:
        get_settings.cache_clear()


# ── Graceful degradation ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_failing_plugin_does_not_crash_load(client):
    """A plugin that raises in register() is logged and skipped; the app boots."""
    import services.capabilities as caps
    from api.main import app

    caps_before = set(caps._CAPABILITIES)

    def _boom(_app):
        raise RuntimeError("plugin exploded")

    ep = MagicMock()
    ep.name = "boom"
    ep.load = MagicMock(return_value=_boom)
    try:
        with patch("services.capabilities.entry_points", return_value=[ep]):
            caps.load_plugins(app)   # must NOT raise
        assert (await client.get("/health")).status_code == 200
    finally:
        caps._CAPABILITIES.clear()
        caps._CAPABILITIES.update(caps_before)


# ── Findings surfaced by the exercise (documenting tests) ───────────────────

def test_finding_plugin_routes_not_rate_limited_by_default():
    """W2: RATE_LIMITED_PREFIXES is a fixed tuple; a plugin route (/v1/ref/*) is
    unlimited unless added. This test records the current state so the W2
    decision (plugins declare a rate-limit class, or plugin routes are
    dashboard-tier) is made consciously. Update it when the decision lands."""
    from api.v1.middleware.rate_limit import RATE_LIMITED_PREFIXES
    assert not "/v1/ref/ping".startswith(RATE_LIMITED_PREFIXES)


def test_finding_ceiling_allowlist_excludes_plugin_capabilities():
    """FINDING: WRAPSEC_FEATURES is validated against a hardcoded
    CONFIGURABLE_CAPABILITIES allowlist that does NOT include plugin-registered
    capabilities. A deployment therefore cannot name a plugin capability
    (e.g. 'ref.ping') in the ceiling without a validation error -- the ceiling
    can only restrict the core-known set. Fine when the ceiling is unset (all
    allowed), but the valid set should incorporate registered plugin
    capabilities for the ceiling to gate them. Update when addressed."""
    from config.settings import CONFIGURABLE_CAPABILITIES
    assert "ref.ping" not in CONFIGURABLE_CAPABILITIES


def test_connector_registration_seam(monkeypatch):
    """Seam built from refplugin finding F2/W13: a plugin can register a connector
    through the public register_connector without touching private state, and the
    admin-API validation (is_known/get_spec) then recognizes it. Non-shadowing."""
    import services.webhooks.connectors.registry as reg
    from services.webhooks.connectors.registry import (
        AuthKind,
        ConnectorSpec,
        register_connector,
    )

    assert reg.is_known("refsink") is False
    spec = ConnectorSpec("refsink", lambda *a, **k: None, AuthKind.STATIC_TOKEN)
    register_connector(spec)
    try:
        assert reg.is_known("refsink") is True
        assert reg.get_spec("refsink") is spec
        assert "refsink" in reg.KNOWN_CONNECTOR_TYPES
        with pytest.raises(ValueError):        # non-shadowing
            register_connector(spec)
    finally:
        reg._REGISTRY.pop("refsink", None)
        reg.KNOWN_CONNECTOR_TYPES = frozenset(reg._REGISTRY)
