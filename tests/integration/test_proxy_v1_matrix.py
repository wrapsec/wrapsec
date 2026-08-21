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


async def _post_capturing_provider(app, body):
    """
    Post, and hand back the provider client mock alongside the response.

    "Rejected" is only half the requirement. The half that matters is that
    nothing reached the provider on the way to the rejection, and that can only
    be shown by inspecting the client that would have carried it.
    """
    from api.v1.dependencies.db import get_db

    fake_get_db, _ = _patch_config()
    app.dependency_overrides[get_db] = fake_get_db
    try:
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client      = AsyncMock()
            mock_client.post = AsyncMock(return_value=_provider_response("fine"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    headers={"x-api-key": settings.admin_api_key},
                    json=body,
                )
            return resp, mock_client
    finally:
        app.dependency_overrides = {}


async def _post_capturing_forwarded(app, body, headers=None):
    """
    Post, and hand back what was actually forwarded to the provider.

    Asserting on the response says what the caller saw. The question here is
    what the MODEL saw, and only the provider call answers that.
    """
    from api.v1.dependencies.db import get_db

    fake_get_db, _ = _patch_config()
    app.dependency_overrides[get_db] = fake_get_db
    try:
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client      = AsyncMock()
            mock_client.post = AsyncMock(return_value=_provider_response("fine"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    headers={"x-api-key": settings.admin_api_key, **(headers or {})},
                    json=body,
                )
            forwarded = None
            if mock_client.post.call_args is not None:
                forwarded = mock_client.post.call_args.kwargs.get("json")
            return resp, forwarded
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
        ("tools",                []),
        ("tool_choice",          "auto"),
        ("functions",            []),
        # The deprecated spelling and the newer companion flag. Neither is named
        # in the schema; the request contract forbids unknown fields, so the
        # whole family is refused by construction rather than by a list somebody
        # has to keep adding to as the provider API grows.
        ("function_call",        "auto"),
        ("parallel_tool_calls",  True),
    ])
    async def test_native_tool_calling_is_refused(self, app, field, value):
        resp = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
            field:      value,
        })
        assert resp.status_code == 422

    # ── Message roles ─────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    @pytest.mark.parametrize("messages", [
        pytest.param([{"role": "tool", "content": "tool output"}], id="alone"),
        pytest.param(
            [{"role": "user", "content": "hi"}, {"role": "tool", "content": "tool output"}],
            id="mixed-with-valid",
        ),
        pytest.param(
            [{"role": "tool", "content": "tool output"}, {"role": "user", "content": "hi"}],
            id="before-valid",
        ),
    ])
    async def test_a_tool_message_is_refused(self, app, messages):
        """
        A tool message carries content the scanner has no trust classification
        for. Forwarding it would put text the proxy never inspected in front of
        the model, which is the outcome the proxy exists to prevent. Refusing
        also keeps this consistent with native tool calling being refused: one
        deferred feature, not a rejected parameter beside an open side door.
        """
        resp = await _post(app, {"model": "openai/gpt-4o", "messages": messages})
        assert resp.status_code == 422
        # refused, not answered
        assert "choices" not in resp.text

    @pytest.mark.asyncio
    async def test_a_tool_message_is_refused_with_scan_all(self, app):
        """The header selects what is scanned; it cannot widen what is accepted."""
        from api.v1.dependencies.db import get_db

        fake_get_db, _ = _patch_config()
        app.dependency_overrides[get_db] = fake_get_db
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    headers={
                        "x-api-key":                     settings.admin_api_key,
                        "X-WrapSec-Scan-All-Messages":   "true",
                    },
                    json={
                        "model": "openai/gpt-4o",
                        "messages": [
                            {"role": "user",      "content": "hi"},
                            {"role": "tool",      "content": "tool output"},
                            {"role": "assistant", "content": "sure"},
                        ],
                    },
                )
        finally:
            app.dependency_overrides = {}
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_a_tool_message_never_reaches_the_provider(self, app):
        """
        The rejection has to happen before the request is acted on. A 422 that
        still forwarded the conversation would refuse the caller while doing the
        very thing the refusal is for.
        """
        resp, provider = await _post_capturing_provider(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": "user", "content": "hi"},
                         {"role": "tool", "content": "tool output"}],
        })
        assert resp.status_code == 422
        provider.post.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("role", ["function", "developer", "TOOL", "User", "", None])
    async def test_an_unrecognised_role_is_refused(self, app, role):
        """
        Refusing only the known-bad role would leave the next one to arrive
        passing through. Anything the proxy cannot classify is refused, and the
        comparison is exact: a differently-cased role is not a supported one.
        """
        message = {"content": "hello"} if role is None else {"role": role, "content": "hello"}
        resp = await _post(app, {"model": "openai/gpt-4o", "messages": [message]})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    @pytest.mark.parametrize("role", ["user", "assistant"])
    async def test_a_supported_role_is_not_refused_as_unsupported(self, app, role):
        """
        Being an accepted ROLE and having something SCANNABLE are different
        questions, and only the first is this section's. An assistant-only
        conversation is refused under the default posture because nothing in it
        is inspected -- but with 400, not the 422 that means "we do not accept
        this role at all".
        """
        resp = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": role, "content": "what is the capital of France?"}],
        })
        assert resp.status_code != 422, f"{role} was refused as an unsupported role"

    @pytest.mark.asyncio
    async def test_an_ordinary_conversation_with_an_assistant_turn_is_served(self, app):
        """The shape a real caller sends: history, ending on the new question."""
        resp = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [
                {"role": "user",      "content": "what is the capital of France?"},
                {"role": "assistant", "content": "Paris."},
                {"role": "user",      "content": "and of Spain?"},
            ],
        })
        assert resp.status_code == 200, resp.text

    @pytest.mark.asyncio
    async def test_a_system_message_is_still_accepted(self, app):
        """
        System keeps its existing treatment: accepted, forwarded, not scanned.
        Pinned so tightening the role contract cannot change it as a side
        effect -- that would break callers whose prompt lives in a system turn.
        """
        resp = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": "system",  "content": "You are terse."},
                         {"role": "user",    "content": "hello"}],
        })
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_native_tool_calling_and_tool_messages_are_separate_controls(self, app):
        """
        Two doors, each closed on its own. A request may present either without
        the other, so neither check may rely on the other being reached first.
        """
        # the parameter, with only supported roles present
        by_param = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "tools":    [],
        })
        # the role, with no tool-calling parameter present
        by_role = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": "tool", "content": "out"}],
        })
        assert by_param.status_code == 422
        assert by_role.status_code  == 422

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


# ── Refusals before inspection are counted, not written to the decision trail ──

class TestPreInspectionRefusals:
    """
    These never reach detection. Recording them as decisions would need an
    invented decision, and that trail's numbers are what block-rate and threat
    analytics are built from, so they are counted and logged instead.
    """

    def _count(self, reason: str) -> float:
        from observability.metrics import PROXY_REJECTED
        return PROXY_REJECTED.labels(reason=reason)._value.get()

    @pytest.mark.asyncio
    async def test_a_refusal_increments_its_reason(self, app):
        before = self._count("provider_mismatch")

        resp = await _post(app, {
            "model":    "ollama/llama3",           # tenant is configured for openai
            "messages": [{"role": "user", "content": "hi"}],
        })

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "provider_mismatch"
        assert self._count("provider_mismatch") == before + 1

    @pytest.mark.asyncio
    async def test_reasons_are_counted_separately(self, app):
        """A single lump counter cannot tell a client bug from a broken tenant."""
        before = self._count("invalid_messages")

        resp = await _post(app, {
            "model":    "openai/gpt-4o",
            "messages": [{"role": "system", "content": "only a system prompt"}],
        })

        assert resp.status_code == 400
        assert self._count("invalid_messages") == before + 1

    @pytest.mark.asyncio
    async def test_a_refusal_writes_no_decision_row(self, app):
        """
        The assertion that matters: nothing lands in the decision trail. A row
        there would inflate block-rate with requests where no content was ever
        examined.
        """
        created = []

        async def _capture(self, data):
            created.append(data)

        with patch("db.repositories.audit.AuditRepository.create", new=_capture):
            resp = await _post(app, {
                "model":    "ollama/llama3",
                "messages": [{"role": "user", "content": "hi"}],
            })

        assert resp.status_code == 400
        assert created == [], "a refusal that was never inspected reached the decision trail"


# ── Assistant scanning, the opt-in capability ─────────────────────────────────

class TestAssistantScanning:
    """
    Off by default, so both postures are pinned: what ships, and what the
    capability does when an operator turns it on.

    The enabled path is exercised with the flag actually set rather than by
    calling the extraction helper directly. A capability that is only ever
    tested through its internals is one nobody has confirmed is reachable.
    """

    @staticmethod
    def _conversation():
        # The email is what makes this deterministic: the PII guardrail redacts
        # it, so the decision is SANITIZE without depending on a model's score.
        return [
            {"role": "system",    "content": "You are terse."},
            {"role": "user",      "content": "what did we agree?"},
            {"role": "assistant", "content": "Contact me at alice@example.com about the invoice"},
        ]

    @pytest.mark.asyncio
    async def test_the_default_does_not_scan_an_assistant_turn(self, app, monkeypatch):
        """
        The shipped posture. The assistant turn reaches the model exactly as it
        was sent, which is the known gap the capability exists to close.
        """
        monkeypatch.setenv("SCAN_ASSISTANT_MESSAGES", "false")
        get_settings.cache_clear()
        try:
            resp, forwarded = await _post_capturing_forwarded(app, {
                "model": "openai/gpt-4o", "messages": self._conversation(),
            })
            assert resp.status_code == 200, resp.text
            assert forwarded is not None, "nothing reached the provider"
            assert forwarded["messages"][2]["content"] == self._conversation()[2]["content"]
            assert "alice@example.com" in forwarded["messages"][2]["content"]
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_enabling_it_rewrites_the_assistant_turn_in_place(self, app, monkeypatch):
        """
        The capability's whole point: what was scanned is what gets forwarded.
        Forwarding the original after deciding to sanitize it would make the
        decision cosmetic.
        """
        monkeypatch.setenv("SCAN_ASSISTANT_MESSAGES", "true")
        get_settings.cache_clear()
        try:
            resp, forwarded = await _post_capturing_forwarded(app, {
                "model": "openai/gpt-4o", "messages": self._conversation(),
            })
            assert resp.status_code == 200, resp.text
            assistant = forwarded["messages"][2]["content"]
            assert "alice@example.com" not in assistant, "the original reached the model"
            assert "REDACTED" in assistant
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_the_rewrite_lands_on_that_message_and_no_other(self, app, monkeypatch):
        """
        Position matters: the index addresses the original array, which contains
        roles that were never scanned. An off-by-one would rewrite the system
        prompt with the assistant's redacted text.
        """
        monkeypatch.setenv("SCAN_ASSISTANT_MESSAGES", "true")
        get_settings.cache_clear()
        try:
            original = self._conversation()
            _resp, forwarded = await _post_capturing_forwarded(app, {
                "model": "openai/gpt-4o", "messages": original,
            })
            assert forwarded["messages"][0] == original[0], "the system prompt was altered"
            assert forwarded["messages"][1] == original[1], "the user turn was altered"
            assert [m["role"] for m in forwarded["messages"]] == \
                   [m["role"] for m in original], "roles were reordered or dropped"
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_the_caller_array_is_not_mutated(self, app, monkeypatch):
        """The rewrite builds a new array; the request body is left alone."""
        monkeypatch.setenv("SCAN_ASSISTANT_MESSAGES", "true")
        get_settings.cache_clear()
        try:
            original = self._conversation()
            sent     = [dict(m) for m in original]
            await _post_capturing_forwarded(app, {
                "model": "openai/gpt-4o", "messages": sent,
            })
            assert sent == original
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_a_conversation_ending_on_an_assistant_turn_still_scans(self, app, monkeypatch):
        """
        With the capability off the last scanned message is the last USER turn,
        not the last message. Falling through to nothing would refuse an
        ordinary conversation.
        """
        monkeypatch.setenv("SCAN_ASSISTANT_MESSAGES", "false")
        get_settings.cache_clear()
        try:
            resp, forwarded = await _post_capturing_forwarded(app, {
                "model": "openai/gpt-4o",
                "messages": [
                    {"role": "user",      "content": "what is the capital of France?"},
                    {"role": "assistant", "content": "Paris."},
                ],
            })
            assert resp.status_code == 200, resp.text
            assert forwarded is not None
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_an_assistant_only_conversation_is_refused_by_default(self, app, monkeypatch):
        """
        Nothing scannable means nothing to forward. Passing it through would
        send the model content the proxy never inspected.
        """
        monkeypatch.setenv("SCAN_ASSISTANT_MESSAGES", "false")
        get_settings.cache_clear()
        try:
            resp = await _post(app, {
                "model": "openai/gpt-4o",
                "messages": [{"role": "assistant", "content": "hello"}],
            })
            assert resp.status_code == 400
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_the_same_conversation_is_accepted_when_enabled(self, app, monkeypatch):
        monkeypatch.setenv("SCAN_ASSISTANT_MESSAGES", "true")
        get_settings.cache_clear()
        try:
            resp = await _post(app, {
                "model": "openai/gpt-4o",
                "messages": [{"role": "assistant", "content": "hello"}],
            })
            assert resp.status_code == 200, resp.text
        finally:
            get_settings.cache_clear()
