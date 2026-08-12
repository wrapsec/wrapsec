# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
RBAC role-authorization matrix (V1).

Verifies the authoritative V1 policy (see docs/internal/rbac_matrix_v1.md):
mutations of admin resources require ADMIN; non-admin roles (Developer, Auditor,
Viewer) and API keys are rejected with 403. Auditor is confirmed read-only.
Role escalation and mass assignment of authorization-sensitive fields are
blocked. Reads-open-to-any-authenticated-tenant-user is the confirmed V1 policy
and is exercised elsewhere; this suite focuses on the negative (denial) paths.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from config.settings import get_settings
from db.models import UserModel
from services.auth.token import create_access_token

pytestmark = pytest.mark.asyncio

settings = get_settings()
DUMMY = "00000000-0000-0000-0000-000000000000"


def _sf():
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    return engine, async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _make_user_token(tenant_id, role: str, *, dept_id=None) -> tuple[uuid.UUID, str]:
    """Create a real user of `role` (middleware resolves role from the DB) and
    return (id, access token). Cleaned up by the caller or auth_setup."""
    uid = uuid.uuid4()
    engine, sf = _sf()
    try:
        async with sf() as db:
            db.add(UserModel(
                id=uid, tenant_id=tenant_id, dept_id=dept_id,
                email=f"{role.lower()}-{uuid.uuid4().hex[:6]}@test.com",
                password_hash="x", role=role, token_version=1,
            ))
            await db.commit()
    finally:
        await engine.dispose()
    m = MagicMock()
    m.id = uid; m.tenant_id = tenant_id; m.dept_id = dept_id; m.role = role; m.token_version = 1
    return uid, create_access_token(m)


@pytest_asyncio.fixture
async def auditor_token(auth_setup) -> str:
    _uid, token = await _make_user_token(auth_setup["tenant"].id, "AUDITOR")
    return token


# Admin-only mutation endpoints, with schema-valid bodies so the only possible
# failure is the authorization 403 (never a 422). Path ids are dummies -- the
# require_admin dependency rejects before any resource lookup.
ADMIN_ONLY = [
    ("post",   "/v1/admin/users",                          {"email": "x@y.com", "password": "ValidPass123!", "role": "ADMIN"}),
    ("patch",  f"/v1/admin/users/{DUMMY}",                 {"is_active": False}),
    ("post",   f"/v1/admin/users/{DUMMY}/reset-password",  {"new_password": "ValidPass123!"}),
    ("post",   "/v1/admin/departments",                    {"name": "D", "slug": "d-slug"}),
    ("put",    f"/v1/admin/departments/{DUMMY}",           {"name": "D2"}),
    ("delete", f"/v1/admin/departments/{DUMMY}",           None),
    ("post",   "/v1/admin/applications",                   {"dept_id": DUMMY, "name": "A", "slug": "a-slug"}),
    ("put",    f"/v1/admin/applications/{DUMMY}",          {"name": "A2"}),
    ("delete", f"/v1/admin/applications/{DUMMY}",          None),
    ("put",    "/v1/admin/tenant",                         {"name": "T"}),
    ("post",   "/v1/admin/webhooks",                       {"url": "https://example.com/hook"}),
    ("delete", f"/v1/admin/webhooks/{DUMMY}",              None),
    ("put",    "/v1/settings/thresholds",                  {"block_threshold": 0.7, "sanitize_threshold": 0.4}),
    ("put",    "/v1/admin/email/settings",                 {"notifications_enabled": True, "max_attempts": 8, "retention_days": 30}),
]


@pytest.mark.parametrize("method,path,body", ADMIN_ONLY, ids=lambda v: v if isinstance(v, str) else "")
async def test_non_admin_roles_denied_on_admin_endpoints(auth_client, auth_setup, auditor_token, method, path, body):
    roles = {
        "developer": auth_setup["dev_token"],
        "viewer":    auth_setup["viewer_token"],
        "auditor":   auditor_token,
    }
    for role, token in roles.items():
        resp = await auth_client.request(method.upper(), path, json=body, headers=_bearer(token))
        assert resp.status_code == 403, f"{role} {method} {path} -> {resp.status_code} (expected 403)"


@pytest.mark.parametrize("method,path,body", ADMIN_ONLY, ids=lambda v: v if isinstance(v, str) else "")
async def test_api_key_denied_on_admin_endpoints(auth_client, auth_setup, method, path, body):
    # require_admin implies JWT; an API key (even the admin key) is rejected.
    resp = await auth_client.request(method.upper(), path, json=body, headers={"x-api-key": settings.admin_api_key})
    assert resp.status_code == 403, f"api_key {method} {path} -> {resp.status_code} (expected 403)"


# -- AUDITOR is read-only -------------------------------------------
async def test_auditor_can_read_audit_and_email_delivery(auth_client, auth_setup, auditor_token):
    for path in ("/v1/audit/logs", "/v1/admin/email"):
        resp = await auth_client.get(path, headers=_bearer(auditor_token))
        assert resp.status_code == 200, f"auditor GET {path} -> {resp.status_code} (expected 200)"


# -- role escalation blocked ----------------------------------------
async def test_developer_cannot_escalate_self_to_admin(auth_client, auth_setup):
    dev_id = str(auth_setup["dev_user"].id)
    resp = await auth_client.request(
        "PATCH", f"/v1/admin/users/{dev_id}",
        json={"role": "ADMIN"},
        headers=_bearer(auth_setup["dev_token"]),
    )
    assert resp.status_code == 403


async def test_viewer_cannot_promote_another_user(auth_client, auth_setup):
    dev_id = str(auth_setup["dev_user"].id)
    resp = await auth_client.request(
        "PATCH", f"/v1/admin/users/{dev_id}",
        json={"role": "ADMIN"},
        headers=_bearer(auth_setup["viewer_token"]),
    )
    assert resp.status_code == 403


# -- mass assignment ------------------------------------------------
async def test_tenant_id_is_ignored_in_user_patch(auth_client, auth_setup):
    # An admin PATCH carrying tenant_id must not move the user: the field is not
    # on UserPatchSchema, so it is dropped -- the request becomes a no-op and the
    # user's tenant is unchanged.
    viewer_id = str(auth_setup["viewer_user"].id)
    own_tenant = str(auth_setup["tenant"].id)
    resp = await auth_client.request(
        "PATCH", f"/v1/admin/users/{viewer_id}",
        json={"tenant_id": str(uuid.uuid4())},
        headers=_bearer(auth_setup["admin_token"]),
    )
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == own_tenant  # unchanged
