# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
`/health/config` discloses configuration according to permission.

`GET /v1/settings` is guarded by `require_permission("settings:read")` with
trial keys refused, because thresholds and layer status are calibration data: a
caller who knows the block threshold knows exactly how far under it a payload
has to sit. `/health/config` returned the same values behind
`get_current_principal` alone, so any authenticated caller -- a trial key, a
VIEWER -- read what that guard exists to withhold, and the restriction on
`/v1/settings` protected nothing.

The route still admits everyone, because deployment verification is its purpose
and gating it entirely would break that for the callers most likely to need it.
The BODY is what varies.

These tests drive the endpoint directly with a constructed principal, so each
caller class is exercised in isolation rather than through a stack.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from api.v1.endpoints.health import health_config
from domain.entities.principal import ROLE_PERMISSIONS, Principal
from domain.enums import PrincipalType

# Fields that duplicate what /v1/settings serves behind settings:read.
RESTRICTED = {
    "thresholds":       {"block", "sanitize"},
    "detection_layers": {"rule", "ml", "llm"},
    "llm":              {"provider", "model", "llm_trigger", "timeout"},
    "rate_limit":       {"per_minute"},
}


def _request(*, role: str | None, principal_type: str, key_type: str = "live"):
    """A request whose state carries one caller class."""
    req = SimpleNamespace()
    req.state = SimpleNamespace(
        principal_type = principal_type,
        tenant_id      = "11111111-1111-1111-1111-111111111111",
        dept_id        = None,
        key_id         = "user:x" if principal_type == "user" else "key:wsk_x",
        key_name       = "caller",
        user_role      = role,
        is_admin       = role == "ADMIN",
        key_type       = key_type,
    )
    return req


def _principal(role: str | None, principal_type: str) -> Principal:
    return Principal(
        id          = "user:x" if principal_type == "user" else "key:wsk_x",
        type        = PrincipalType.USER if principal_type == "user" else PrincipalType.API_KEY,
        tenant_id   = "11111111-1111-1111-1111-111111111111",
        dept_id     = None,
        roles       = [role] if role else ["DEVELOPER"],
        permissions = ROLE_PERMISSIONS.get(role or "DEVELOPER", []),
        is_admin    = role == "ADMIN",
    )


async def _call(*, role: str | None, principal_type: str = "user", key_type: str = "live"):
    req = _request(role=role, principal_type=principal_type, key_type=key_type)
    repo = SimpleNamespace(get=AsyncMock(return_value=None))   # nothing stored -> env defaults
    with patch("api.v1.endpoints.settings._resolve_tenant",
               AsyncMock(return_value="11111111-1111-1111-1111-111111111111")), \
         patch("db.repositories.settings.TenantSettingsRepository", lambda _db: repo):
        return await health_config(req, db=None, _principal=_principal(role, principal_type))


def _restricted_present(body: dict) -> set[str]:
    """Which restricted fields leaked into this body."""
    leaked = set()
    for section, fields in RESTRICTED.items():
        for field in fields:
            if field in body.get(section, {}):
                leaked.add(f"{section}.{field}")
    return leaked


# ── holders of settings:read keep full access ────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["ADMIN", "DEVELOPER", "AUDITOR"])
async def test_settings_readers_retain_full_access(role):
    body = await _call(role=role)
    missing = set()
    for section, fields in RESTRICTED.items():
        missing |= {f"{section}.{f}" for f in fields if f not in body.get(section, {})}
    assert not missing, f"{role} holds settings:read but lost {sorted(missing)}"


# ── callers without it get the reduced body ──────────────────────────────────

@pytest.mark.asyncio
async def test_viewer_cannot_read_restricted_fields():
    """VIEWER holds audit:read and dashboard:read, never settings:read."""
    body = await _call(role="VIEWER")
    assert not _restricted_present(body), (
        f"VIEWER read calibration data: {sorted(_restricted_present(body))}"
    )


@pytest.mark.asyncio
async def test_trial_key_cannot_read_thresholds_or_layer_status():
    """
    A trial key carries DEVELOPER permissions on the API-key path, so the role
    alone would admit it. The trial check is the reason it must not -- the same
    reason `/v1/settings` refuses it.
    """
    body = await _call(role=None, principal_type="api_key", key_type="trial")
    leaked = _restricted_present(body)
    assert not leaked, f"a trial key read calibration data: {sorted(leaked)}"


@pytest.mark.asyncio
async def test_a_live_api_key_with_the_permission_still_reads_it():
    """The trial check must not accidentally restrict every API key."""
    body = await _call(role=None, principal_type="api_key", key_type="live")
    assert "block" in body["thresholds"]


# ── the split keeps the endpoint useful ──────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("role,ptype,ktype", [
    ("VIEWER", "user", "live"),
    (None, "api_key", "trial"),
])
async def test_deployment_verification_still_works_for_every_class(role, ptype, ktype):
    """
    Gating the whole route would have been simpler and wrong: every caller must
    still be able to confirm which build is running and whether configuration
    is customised.
    """
    body = await _call(role=role, principal_type=ptype, key_type=ktype)
    assert body["version"], "version withheld -- deployment verification broken"
    for section in RESTRICTED:
        assert body[section]["source"] in ("database", "environment"), (
            f"{section}.source withheld -- cannot tell customised from default"
        )


@pytest.mark.asyncio
async def test_no_secret_ever_appears_for_any_caller():
    for role, ptype, ktype in [("ADMIN", "user", "live"), ("VIEWER", "user", "live"),
                               (None, "api_key", "trial")]:
        body = await _call(role=role, principal_type=ptype, key_type=ktype)
        flat = str(body).lower()
        for banned in ("api_key", "secret", "password", "token"):
            assert banned not in flat, f"{banned} present for {role or ktype}"
