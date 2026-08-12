# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Integration tests for locale preference (Phase 2).

Exercises the user (/v1/auth/me) and tenant (/v1/admin/tenant) locale plumbing:
expose, set, persist, reject unsupported. Backend stays English-only; only the
preference + resolved_locale are surfaced.
"""
import pytest


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_login_returns_resolved_locale(auth_client, auth_setup):
    email = auth_setup["admin_user"].email
    r = await auth_client.post("/v1/auth/login", json={"email": email, "password": "TestPass1!"})
    assert r.status_code == 200
    assert r.json()["resolved_locale"] == "en"   # BFF sets the wrapsec_locale cookie from this


@pytest.mark.asyncio
async def test_refresh_returns_resolved_locale(auth_client, auth_setup):
    email   = auth_setup["admin_user"].email
    login_r = await auth_client.post("/v1/auth/login", json={"email": email, "password": "TestPass1!"})
    assert login_r.status_code == 200
    raw_cookie = login_r.cookies.get("refresh_token")
    assert raw_cookie

    r = await auth_client.post("/v1/auth/refresh", cookies={"refresh_token": raw_cookie})
    assert r.status_code == 200
    # Locale is re-resolved on every refresh (User -> Tenant -> System -> English).
    assert r.json()["resolved_locale"] == "en"


@pytest.mark.asyncio
async def test_me_exposes_locale_and_resolved(auth_client, auth_setup):
    token = auth_setup["admin_token"]
    r = await auth_client.get("/v1/auth/me", headers=_auth(token))
    assert r.status_code == 200
    data = r.json()
    assert data["locale"] is None            # no preference stored yet
    assert data["resolved_locale"] == "en"   # falls through to the system default


@pytest.mark.asyncio
async def test_patch_me_sets_and_persists_locale(auth_client, auth_setup):
    token = auth_setup["admin_token"]
    r = await auth_client.patch("/v1/auth/me", json={"locale": "en"}, headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["locale"] == "en"
    # persisted across requests
    again = await auth_client.get("/v1/auth/me", headers=_auth(token))
    assert again.json()["locale"] == "en"
    assert again.json()["resolved_locale"] == "en"


@pytest.mark.asyncio
async def test_patch_me_accepts_case_insensitive_and_canonicalizes(auth_client, auth_setup):
    token = auth_setup["admin_token"]
    r = await auth_client.patch("/v1/auth/me", json={"locale": "EN"}, headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["locale"] == "en"   # canonicalized to the allowlist spelling


@pytest.mark.asyncio
async def test_patch_me_clears_locale_with_null(auth_client, auth_setup):
    token = auth_setup["admin_token"]
    await auth_client.patch("/v1/auth/me", json={"locale": "en"}, headers=_auth(token))
    r = await auth_client.patch("/v1/auth/me", json={"locale": None}, headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["locale"] is None


@pytest.mark.asyncio
async def test_patch_me_accepts_de_when_enabled(auth_client, auth_setup):
    # German is now a supported locale (locales/_meta.json), so it is accepted,
    # persisted, and resolved -- no longer the "unsupported" example.
    token = auth_setup["admin_token"]
    r = await auth_client.patch("/v1/auth/me", json={"locale": "de"}, headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["locale"] == "de"
    again = await auth_client.get("/v1/auth/me", headers=_auth(token))
    assert again.json()["locale"] == "de"
    assert again.json()["resolved_locale"] == "de"


@pytest.mark.asyncio
async def test_patch_me_rejects_unsupported_locale(auth_client, auth_setup):
    # 'zz' is unassigned -- a stable stand-in that will never be an allowlisted
    # locale, unlike a real language code that might later be enabled.
    token = auth_setup["admin_token"]
    r = await auth_client.patch("/v1/auth/me", json={"locale": "zz"}, headers=_auth(token))
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "VALIDATION_ERROR"
    assert any(p["field"] == "locale" and p["code"] == "INVALID_ENUM"
               for p in err.get("invalid_params", []))


@pytest.mark.asyncio
async def test_patch_me_rejects_overlong_locale(auth_client, auth_setup):
    # max_length=35 caps the request before the allowlist validator runs; an
    # oversized string is a schema (VALIDATION_ERROR) rejection on the locale field.
    token = auth_setup["admin_token"]
    r = await auth_client.patch("/v1/auth/me", json={"locale": "x" * 36}, headers=_auth(token))
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "VALIDATION_ERROR"
    assert any(p["field"] == "locale" for p in err.get("invalid_params", []))


@pytest.mark.asyncio
async def test_tenant_exposes_and_sets_locale(auth_client, auth_setup):
    token = auth_setup["admin_token"]
    g = await auth_client.get("/v1/admin/tenant", headers=_auth(token))
    assert g.status_code == 200
    assert "locale" in g.json()

    p = await auth_client.put("/v1/admin/tenant", json={"locale": "en"}, headers=_auth(token))
    assert p.status_code == 200
    assert p.json()["locale"] == "en"


@pytest.mark.asyncio
async def test_tenant_rejects_unsupported_locale(auth_client, auth_setup):
    token = auth_setup["admin_token"]
    r = await auth_client.put("/v1/admin/tenant", json={"locale": "zz"}, headers=_auth(token))
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "VALIDATION_ERROR"
    assert any(p["field"] == "locale" and p["code"] == "INVALID_ENUM"
               for p in err.get("invalid_params", []))


@pytest.mark.asyncio
async def test_tenant_rejects_overlong_locale(auth_client, auth_setup):
    # Same max_length(35) boundary as /me: an oversized string is a schema
    # (string_too_long) rejection on the locale field, not the allowlist enum.
    token = auth_setup["admin_token"]
    r = await auth_client.put("/v1/admin/tenant", json={"locale": "x" * 36}, headers=_auth(token))
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "VALIDATION_ERROR"
    assert any(p["field"] == "locale" for p in err.get("invalid_params", []))
