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


# ── AuthProvider seam (increment 2 / 2.8): a plugin identity backend ─────────

@pytest.mark.asyncio
async def test_auth_provider_registration_seam(auth_setup):
    """Seam built for 2.8 (open-core P4): a plugin registers an AuthProvider under
    a NEW method name through the public register_auth_provider, and
    AuthService.login(method=...) routes to it -- proven end to end against a real
    seeded user. Mirrors the connector seam exactly (register -> resolve ->
    non-shadowing) and then exercises the full login path.

    The ref provider delegates to the core password backend: it proves ROUTING
    without introducing a new credential type or any auth weakness -- a plugin
    provider is never a backdoor."""
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )
    from sqlalchemy.pool import NullPool

    import services.auth.providers.registry as areg
    from config.settings import get_settings
    from errors.exceptions import AuthenticationError
    from services.auth.providers import (
        PasswordAuthProvider,
        available_auth_providers,
        get_auth_provider,
        is_known,
        register_auth_provider,
    )
    from services.auth.providers.base import AuthProvider
    from services.auth.service import AuthService

    class RefAuthProvider(AuthProvider):
        @property
        def name(self):
            return "refauth"

        async def authenticate(self, credentials, db):
            return await PasswordAuthProvider().authenticate(credentials, db)

    class _ShadowPassword(AuthProvider):
        # A plugin trying to hijack the built-in backend -- must be refused.
        @property
        def name(self):
            return "password"

        async def authenticate(self, credentials, db):
            raise AssertionError("a shadowing provider must never run")

    assert is_known("refauth") is False
    register_auth_provider(RefAuthProvider())
    try:
        # Registration is visible through the public surface.
        assert isinstance(get_auth_provider("refauth"), RefAuthProvider)
        assert "refauth" in available_auth_providers()
        assert "password" in available_auth_providers()   # built-in always present

        # Non-shadowing: re-registering the same name, or trying to overwrite the
        # built-in "password" backend, both raise -- no auth-bypass foot-gun.
        with pytest.raises(ValueError):
            register_auth_provider(RefAuthProvider())
        with pytest.raises(ValueError):
            register_auth_provider(_ShadowPassword())

        # End to end: login routes THROUGH the plugin method to a real session.
        email  = auth_setup["admin_user"].email
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        sf     = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with sf() as db:
                result = await AuthService().login(
                    email=email, password="TestPass1!", db=db, method="refauth",
                )
            assert result.access_token
            assert result.user.email == email

            # An unknown method fails closed as a generic auth error (never leaks
            # which methods exist, never falls back to a default backend).
            async with sf() as db:
                with pytest.raises(AuthenticationError):
                    await AuthService().login(
                        email=email, password="TestPass1!", db=db,
                        method="does-not-exist",
                    )
        finally:
            await engine.dispose()
    finally:
        areg._PROVIDERS.pop("refauth", None)


# ── Policy-layer seam (increment 2 / 2.9): a plugin plan ceiling ─────────────

@pytest.mark.asyncio
async def test_policy_layer_registration_seam(auth_setup):
    """Seam built for 2.9 (open-core P4): a plugin registers a policy layer that
    runs as a FINAL CEILING after core resolution, and resolve_policy threads the
    resolved policy through it -- proven end to end against a real tenant. Here
    the layer clamps rate_limit by a 'plan' (a billing plugin would read
    tenants.plan via ctx). Without the layer the same call is unchanged, which is
    the OSS invariant: no layer registered -> byte-identical resolution."""
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )
    from sqlalchemy.pool import NullPool

    import services.policy_layers as pl
    from config.settings import get_settings
    from services.policy_layers import register_policy_layer
    from services.policy_resolver import resolve_policy

    tid    = str(auth_setup["tenant"].id)
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    sf     = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    before = list(pl._LAYERS)
    try:
        # OSS baseline: no layer registered -> core default rate limit.
        async with sf() as db:
            baseline, _ = await resolve_policy(db, tenant_id=tid)
        assert baseline["rate_limit"]["per_minute"] == 60

        async def free_plan_ceiling(policy, ctx):
            # A billing plugin resolves ctx.tenant_id -> plan via ctx.db here.
            assert ctx.tenant_id == tid
            capped = min(policy["rate_limit"]["per_minute"], 5)
            return {**policy, "rate_limit": {**policy["rate_limit"], "per_minute": capped}}

        register_policy_layer(free_plan_ceiling)

        async with sf() as db:
            capped, _ = await resolve_policy(db, tenant_id=tid)
        assert capped["rate_limit"]["per_minute"] == 5   # ceiling applied last
    finally:
        pl._LAYERS[:] = before
        await engine.dispose()
