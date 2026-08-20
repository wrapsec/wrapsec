# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Proxy contract requirements that had no test of their own.

The scanning, provenance, provider-failure and source-network behaviours are
covered in their own files. This closes the remaining requirements: that
unsupported features are refused rather than quietly downgraded, that a blocked
response is not released, that every error carries the same envelope, and that
only an administrator of the owning tenant can change where a credential may be
used.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from config.settings import get_settings
from security.encryption import encrypt

settings = get_settings()


def _make_config():
    from datetime import datetime, timezone
    config                      = MagicMock()
    config.tenant_id            = "test_tenant"
    config.provider             = "openai"
    config.base_url             = "https://api.openai.com/v1"
    config.provider_api_key_enc = encrypt("sk-test-key-1234567890", settings.secret_key)
    config.default_model        = "gpt-4o"
    config.timeout_seconds      = 30
    config.created_at           = datetime(2025, 1, 1, tzinfo=timezone.utc)
    config.updated_at           = datetime(2025, 1, 1, tzinfo=timezone.utc)
    return config


def _patch_config():
    result = MagicMock()
    result.scalar_one_or_none.return_value = _make_config()
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.add     = MagicMock()
    db.commit  = AsyncMock()

    async def fake_get_db():
        yield db

    return fake_get_db, db


def _provider_response(content):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "choices": [{"message": {"role": "assistant", "content": content},
                     "finish_reason": "stop", "index": 0}],
        "model": "gpt-4o",
        "id":    "chatcmpl-test",
    }
    return resp


@pytest.fixture
def app():
    from api.main import app
    return app


async def _post(app, body, provider_content="fine"):
    from api.v1.dependencies.db import get_db

    fake_get_db, _ = _patch_config()
    app.dependency_overrides[get_db] = fake_get_db
    try:
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client      = AsyncMock()
            mock_client.post = AsyncMock(return_value=_provider_response(provider_content))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                return await client.post(
                    "/v1/chat/completions",
                    headers={"x-api-key": settings.admin_api_key},
                    json=body,
                )
    finally:
        app.dependency_overrides = {}


# ── Unsupported features are refused, never downgraded ────────────────────────

class TestUnsupportedFeatures:
    """
    Silently dropping an unsupported field would answer a question the caller
    did not ask: a streaming request would return a whole body, and a tool-call
    request would come back as prose.
    """

    @pytest.mark.asyncio
    async def test_streaming_is_refused(self, app):
        resp = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
            "stream":   True,
        })
        assert resp.status_code == 422
        # not honoured as a non-streaming call
        assert "choices" not in resp.text

    @pytest.mark.asyncio
    @pytest.mark.parametrize("field,value", [
        ("tools",       []),
        ("tool_choice", "auto"),
        ("functions",   []),
    ])
    async def test_native_tool_calling_is_refused(self, app, field, value):
        resp = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
            field:      value,
        })
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_a_supported_request_still_works(self, app):
        """The guard above must not reject the surface that is supported."""
        resp = await _post(app, {
            "model":       "openai/gpt-4o",
            "messages":    [{"role": "user", "content": "hello"}],
            "temperature": 0.5,
            "max_tokens":  32,
            "top_p":       0.9,
        })
        assert resp.status_code == 200


# ── A blocked response is not released ────────────────────────────────────────

class TestOutputIsNotReleasedWhenBlocked:

    @pytest.mark.asyncio
    async def test_blocked_output_content_does_not_reach_the_caller(self, app):
        """
        The point of scanning a response is that a caller never sees what the
        guard rejected, so the assertion is on the absence of the content, not
        merely on the status code.
        """
        secret = "My SSN is 123-45-6789 and my card is 4111111111111111"

        resp = await _post(
            app,
            {"model": "openai/gpt-4o", "messages": [{"role": "user", "content": "hello"}]},
            provider_content=secret,
        )

        assert "123-45-6789"     not in resp.text
        assert "4111111111111111" not in resp.text


# ── One error envelope everywhere ─────────────────────────────────────────────

class TestErrorEnvelope:
    """
    Errors keep the shape of the interface the endpoint advertises, so a client
    built for it surfaces a useful message instead of an opaque status, and every
    error carries the correlation id needed to find it in the audit trail.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("body,expected_code", [
        ({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
         "invalid_model_format"),
        ({"model": "openai/gpt-4o", "messages": [{"role": "system", "content": "only system"}]},
         "invalid_messages"),
        ({"model": "ollama/llama3", "messages": [{"role": "user", "content": "hi"}]},
         "provider_mismatch"),
    ])
    async def test_every_client_error_has_the_same_shape(self, app, body, expected_code):
        resp = await _post(app, body)

        assert resp.status_code == 400
        payload = resp.json()
        assert payload["error"]["code"]    == expected_code
        assert payload["error"]["message"]
        assert payload["error"]["type"]
        # the protocol-independent half: correlation, in the body and the header
        assert payload["wrapsec"]["trace_id"]
        assert resp.headers.get("X-WrapSec-Trace-Id")

    @pytest.mark.asyncio
    async def test_a_successful_response_also_carries_the_trace_header(self, app):
        resp = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
        })
        assert resp.status_code == 200
        assert resp.headers.get("X-WrapSec-Trace-Id")


# ── Only an administrator of the owning tenant may change the restriction ─────

def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


class TestAllowlistAuthorisation:
    """
    Whoever can change where a credential may be used can also remove the
    restriction, so the write is confined to administrators of the owning tenant.
    """

    @pytest.mark.asyncio
    async def test_a_developer_cannot_create_a_key(self, auth_client, auth_setup):
        resp = await auth_client.post(
            "/v1/keys",
            headers=_bearer(auth_setup["dev_token"]),
            json={"name": "k", "ip_allowlist": ["10.0.0.0/8"]},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_a_viewer_cannot_create_a_key(self, auth_client, auth_setup):
        resp = await auth_client.post(
            "/v1/keys",
            headers=_bearer(auth_setup["viewer_token"]),
            json={"name": "k", "ip_allowlist": ["10.0.0.0/8"]},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_a_developer_cannot_change_an_allowlist(self, auth_client, auth_setup):
        resp = await auth_client.put(
            "/v1/keys/wsk_nonexistent",
            headers=_bearer(auth_setup["dev_token"]),
            json={"name": "k", "ip_allowlist": []},
        )
        # refused for lack of role, before the key is even looked up
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_an_administrator_of_another_tenant_cannot_change_it(
        self, auth_client, auth_setup, test_db,
    ):
        """
        A key belonging to another tenant must not be reachable, and the answer
        must not confirm that it exists.
        """
        import uuid as _uuid

        from db.models import TenantModel
        from db.repositories.membership import MembershipRepository
        from db.repositories.user import UserRepository
        from services.auth.password import hash_password, normalize_email
        from services.auth.token import create_access_token

        created = await auth_client.post(
            "/v1/keys",
            headers=_bearer(auth_setup["admin_token"]),
            json={
                "name":         "victim",
                "dept_id":      str(auth_setup["dept"].id),
                "ip_allowlist": ["10.0.0.0/8"],
            },
        )
        assert created.status_code in (200, 201), created.text
        key_id = created.json()["key_id"]

        # A real administrator, of a real but different tenant.
        other_tenant = _uuid.uuid4()
        test_db.add(TenantModel(
            id=other_tenant, slug=f"other-{_uuid.uuid4().hex[:8]}", name="Other Tenant",
        ))
        await test_db.flush()
        stranger = await UserRepository(test_db).create({
            "email":         normalize_email(f"other-{_uuid.uuid4().hex[:6]}@test.com"),
            "password_hash": hash_password("TestPass1!"),
        })
        await test_db.flush()
        await MembershipRepository(test_db).upsert_for_user(
            stranger.id, other_tenant, "ADMIN", None,
        )
        await test_db.commit()

        membership = type("M", (), {
            "id":            stranger.id,
            "tenant_id":     other_tenant,
            "dept_id":       None,
            "role":          "ADMIN",
            "token_version": 1,
        })()
        other_token = create_access_token(membership, membership)

        resp = await auth_client.put(
            f"/v1/keys/{key_id}",
            headers=_bearer(other_token),
            json={"name": "victim", "ip_allowlist": []},
        )
        assert resp.status_code == 404
