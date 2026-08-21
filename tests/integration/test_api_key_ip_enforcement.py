# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Where a credential may be presented from, enforced at authentication.

The restriction belongs to the credential, not to a route. Enforced in a
handler it would only ever cover the handlers that remembered to check, and a
credential confined to one network would still be accepted everywhere else --
which is exactly what happened before this moved: the proxy refused, and every
other endpoint accepted the same key from the same denied address.

So the property under test is not "the proxy refuses". It is that the refusal
happens before routing, which is what makes it true of endpoints that do not
exist yet.

These drive the real middleware with a real key row and a real peer address,
rather than putting values on request.state. State can be set to anything; the
question is whether the address a socket actually presents is the one that gets
checked.
"""

import hashlib
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from config.settings import get_settings

# TEST-NET-1/2/3, reserved for documentation. Using them keeps the fixtures from
# depending on whatever the test host's own addressing looks like.
ALLOWED_IP   = "203.0.113.9"
DENIED_IP    = "198.51.100.7"
ALLOWED_NET  = "203.0.113.0/24"


@pytest.fixture
def app():
    from api.main import app
    return app


async def _seed_key(test_db, allowlist, *, tenant_id=None):
    """A real, hash-matching key row, so the middleware resolves it for real."""
    from db.models import APIKeyModel, DepartmentModel, TenantModel

    tid = tenant_id or uuid.uuid4()
    did = uuid.uuid4()
    raw = "wsk_live_" + uuid.uuid4().hex

    if tenant_id is None:
        test_db.add(TenantModel(id=tid, slug=f"t-{tid.hex[:8]}", name="T"))
        await test_db.commit()
    test_db.add(DepartmentModel(id=did, tenant_id=tid, slug=f"d-{did.hex[:6]}",
                                name="D", is_active=True))
    await test_db.commit()
    test_db.add(APIKeyModel(
        id=uuid.uuid4(), key_id="key_" + uuid.uuid4().hex[:12],
        tenant_id=tid, dept_id=did, name="k",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_type="live", is_admin=False, revoked=False,
        ip_allowlist=allowlist,
    ))
    await test_db.commit()
    return raw, tid


async def _request(app, *, api_key, peer_ip, path="/v1/ai/request", headers=None,
                   json_body=None):
    """
    Send a request whose PEER address is peer_ip.

    The address is put on the ASGI scope rather than in a header, because a
    header is the thing a caller controls and the thing this control must not
    believe.
    """
    transport = ASGITransport(app=app, client=(peer_ip, 43210))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(
            path,
            headers={"x-api-key": api_key, **(headers or {})},
            json=json_body if json_body is not None else {"input": "hello"},
        )


# ── The control itself ────────────────────────────────────────────────────────

class TestSourceNetworkEnforcement:

    @pytest.mark.asyncio
    async def test_an_unrestricted_credential_is_accepted_from_anywhere(self, app, test_db):
        """The control is opt-in; a key without one keeps working."""
        for allowlist in (None, []):
            raw, _ = await _seed_key(test_db, allowlist)
            resp = await _request(app, api_key=raw, peer_ip=DENIED_IP)
            assert resp.status_code == 200, resp.text

    @pytest.mark.asyncio
    async def test_a_listed_address_proceeds(self, app, test_db):
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(app, api_key=raw, peer_ip=ALLOWED_IP)
        assert resp.status_code == 200, resp.text

    @pytest.mark.asyncio
    async def test_an_unlisted_address_is_refused(self, app, test_db):
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(app, api_key=raw, peer_ip=DENIED_IP)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_a_single_address_entry_matches_only_that_address(self, app, test_db):
        raw, _ = await _seed_key(test_db, [f"{ALLOWED_IP}/32"])
        assert (await _request(app, api_key=raw, peer_ip=ALLOWED_IP)).status_code == 200
        # one address along in the same /24
        assert (await _request(app, api_key=raw, peer_ip="203.0.113.10")).status_code == 403

    @pytest.mark.asyncio
    async def test_a_network_entry_matches_the_whole_network(self, app, test_db):
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        for addr in ("203.0.113.1", "203.0.113.128", "203.0.113.254"):
            assert (await _request(app, api_key=raw, peer_ip=addr)).status_code == 200
        assert (await _request(app, api_key=raw, peer_ip="203.0.114.1")).status_code == 403

    @pytest.mark.asyncio
    async def test_any_one_entry_is_enough(self, app, test_db):
        raw, _ = await _seed_key(test_db, ["10.0.0.0/8", f"{ALLOWED_IP}/32"])
        assert (await _request(app, api_key=raw, peer_ip=ALLOWED_IP)).status_code == 200
        assert (await _request(app, api_key=raw, peer_ip="10.1.2.3")).status_code == 200
        assert (await _request(app, api_key=raw, peer_ip=DENIED_IP)).status_code == 403


class TestDualStackClients:
    """
    On a dual-stack listener an IPv4 client arrives as `::ffff:203.0.113.9`.

    Every other test here presents a plain IPv4 peer, which is what made this
    invisible: the address is supplied by the harness, and a harness that only
    ever supplies one form cannot see a control that mishandles the other. The
    real e2e round trip missed it too, because Docker's bridge hands the API a
    plain IPv4 peer.
    """

    @pytest.mark.asyncio
    async def test_a_mapped_client_is_allowed_by_its_ipv4_entry(self, app, test_db):
        """
        The lockout case. The operator allowlists the address they see; without
        unmapping, every request from it is refused.
        """
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(app, api_key=raw, peer_ip=f"::ffff:{ALLOWED_IP}")
        assert resp.status_code == 200, resp.text

    @pytest.mark.asyncio
    async def test_a_mapped_client_outside_the_list_is_still_refused(self, app, test_db):
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(app, api_key=raw, peer_ip=f"::ffff:{DENIED_IP}")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_a_genuine_ipv6_client_is_judged_as_ipv6(self, app, test_db):
        raw, _ = await _seed_key(test_db, ["2001:db8::/32"])
        assert (await _request(app, api_key=raw, peer_ip="2001:db8::1")).status_code == 200
        assert (await _request(app, api_key=raw, peer_ip="2001:db9::1")).status_code == 403


# ── The address that gets checked is the one that cannot be claimed ───────────

class TestForwardedHeaders:
    """
    A forwarded header is believed only from a configured trusted proxy. If it
    were believed unconditionally, the whole control would be advisory: a caller
    would name an approved address and be let in.
    """

    @pytest.mark.asyncio
    async def test_a_forwarded_header_from_an_untrusted_peer_is_ignored(self, app, test_db):
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(
            app, api_key=raw, peer_ip=DENIED_IP,
            headers={"X-Forwarded-For": ALLOWED_IP},
        )
        assert resp.status_code == 403, "a claimed address was believed"

    @pytest.mark.asyncio
    async def test_a_forwarded_header_cannot_deny_an_allowed_peer_either(self, app, test_db):
        """The header is ignored in both directions, not just the useful one."""
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(
            app, api_key=raw, peer_ip=ALLOWED_IP,
            headers={"X-Forwarded-For": DENIED_IP},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_a_trusted_proxy_supplies_the_address(self, app, test_db, monkeypatch):
        """
        Behind a configured proxy the peer is the proxy, so the caller's address
        has to come from the header or every request would be judged by the
        proxy's own address.
        """
        proxy_ip = "192.0.2.10"
        monkeypatch.setenv("TRUSTED_PROXY_IPS", proxy_ip)
        get_settings.cache_clear()
        try:
            raw, _ = await _seed_key(test_db, [ALLOWED_NET])

            allowed = await _request(
                app, api_key=raw, peer_ip=proxy_ip,
                headers={"X-Forwarded-For": ALLOWED_IP},
            )
            denied = await _request(
                app, api_key=raw, peer_ip=proxy_ip,
                headers={"X-Forwarded-For": DENIED_IP},
            )
            assert allowed.status_code == 200, allowed.text
            assert denied.status_code  == 403
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_a_client_cannot_prepend_an_approved_address(self, app, test_db, monkeypatch):
        """
        A proxy APPENDS the peer it saw, so the rightmost entry is the trustworthy
        one. Reading the leftmost would let a caller behind a correctly configured
        proxy inject an approved address ahead of its own.
        """
        proxy_ip = "192.0.2.10"
        monkeypatch.setenv("TRUSTED_PROXY_IPS", proxy_ip)
        get_settings.cache_clear()
        try:
            raw, _ = await _seed_key(test_db, [ALLOWED_NET])
            resp = await _request(
                app, api_key=raw, peer_ip=proxy_ip,
                headers={"X-Forwarded-For": f"{ALLOWED_IP}, {DENIED_IP}"},
            )
            assert resp.status_code == 403, "the client-supplied leftmost entry was believed"
        finally:
            get_settings.cache_clear()


# ── It is not the proxy's control ─────────────────────────────────────────────

class TestEveryApiKeyEndpoint:

    @pytest.mark.asyncio
    async def test_the_refusal_happens_before_routing(self, app, test_db):
        """
        The strongest statement of "every endpoint": a path that does not exist
        is still refused with 403 rather than 404. Nothing was routed, so no
        handler could have been the thing that checked -- which is what makes
        this true of endpoints not yet written.
        """
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(
            app, api_key=raw, peer_ip=DENIED_IP, path="/v1/no-such-endpoint",
        )
        assert resp.status_code == 403, (
            "the refusal is happening after routing, so it only covers routes that check"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path,body", [
        ("/v1/ai/request",      {"input": "hello"}),
        ("/v1/ai/scan-batch",   {"items": [{"input": "hello"}]}),
        ("/v1/chat/completions", {"model": "openai/gpt-4o",
                                  "messages": [{"role": "user", "content": "hi"}]}),
    ])
    async def test_each_api_key_endpoint_refuses(self, app, test_db, path, body):
        """
        The regression that prompted the move. Before it, only the last of these
        refused, and the first two accepted a credential from an address its
        owner had explicitly excluded.
        """
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(app, api_key=raw, peer_ip=DENIED_IP, path=path,
                              json_body=body)
        assert resp.status_code == 403, f"{path} did not refuse"


# ── Who the control does not apply to ─────────────────────────────────────────

class TestExemptCredentials:

    @pytest.mark.asyncio
    async def test_the_admin_sentinel_is_exempt(self, app, test_db):
        """
        The platform-operator key is not an api_keys row and has no allowlist to
        enforce. Exempt by construction -- it is authenticated on its own path,
        which never reaches the check -- rather than by a condition that could
        be inverted later.
        """
        resp = await _request(
            app, api_key=get_settings().admin_api_key, peer_ip=DENIED_IP,
        )
        assert resp.status_code == 200, resp.text

    @pytest.mark.asyncio
    async def test_a_dashboard_session_is_unaffected(self, app, auth_client, auth_setup):
        """
        An allowlist belongs to an API key. A signed-in user has no key, so a
        session must not be judged against one -- an operator would otherwise
        lock themselves out of the dashboard by restricting a key.
        """
        resp = await auth_client.get(
            "/v1/keys",
            headers={"Authorization": f"Bearer {auth_setup['admin_token']}"},
        )
        assert resp.status_code == 200, resp.text


# ── The refusal leaves an attributable trace ──────────────────────────────────

class TestDenialIsRecorded:

    @pytest.mark.asyncio
    async def test_the_denial_names_the_credential_and_the_address(self, app, test_db):
        """
        A denial that does not say WHICH credential was refused turns revoking
        one key into auditing all of them.
        """
        from sqlalchemy import select

        from db.models import APIKeyModel, AuthEventModel

        raw, tenant_id = await _seed_key(test_db, [ALLOWED_NET])
        key_id = (await test_db.execute(
            select(APIKeyModel.key_id).where(APIKeyModel.tenant_id == tenant_id)
        )).scalar_one()

        assert (await _request(app, api_key=raw, peer_ip=DENIED_IP)).status_code == 403

        row = (await test_db.execute(
            select(AuthEventModel).where(AuthEventModel.tenant_id == tenant_id)
        )).scalar_one()

        assert row.action         == "api_key_ip_denied"
        assert row.success        is False
        assert row.failure_reason == "ip_not_allowed"
        assert row.ip_address     == DENIED_IP
        assert row.key_id         == key_id      # bare, so it joins api_keys
        assert row.user_id is None               # a machine credential has no user

    @pytest.mark.asyncio
    async def test_an_accepted_request_records_no_denial(self, app, test_db):
        """The counterpart: the trail must not fill with events for allowed traffic."""
        from sqlalchemy import select

        from db.models import AuthEventModel

        raw, tenant_id = await _seed_key(test_db, [ALLOWED_NET])
        assert (await _request(app, api_key=raw, peer_ip=ALLOWED_IP)).status_code == 200

        rows = (await test_db.execute(
            select(AuthEventModel).where(AuthEventModel.tenant_id == tenant_id)
        )).scalars().all()
        assert rows == []


# ── One tenant's restriction cannot affect another's ──────────────────────────

class TestTenantIsolation:

    @pytest.mark.asyncio
    async def test_a_restriction_binds_only_its_own_credential(self, app, test_db):
        """
        Two tenants, same address. One restricts, the other does not; the
        unrestricted credential must be unaffected.
        """
        restricted, _   = await _seed_key(test_db, [ALLOWED_NET])
        unrestricted, _ = await _seed_key(test_db, None)

        assert (await _request(app, api_key=restricted,   peer_ip=DENIED_IP)).status_code == 403
        assert (await _request(app, api_key=unrestricted, peer_ip=DENIED_IP)).status_code == 200

    @pytest.mark.asyncio
    async def test_two_credentials_carry_their_own_lists(self, app, test_db):
        """A denial for one address must not be a denial for the other's."""
        a_key, _ = await _seed_key(test_db, [f"{ALLOWED_IP}/32"])
        b_key, _ = await _seed_key(test_db, [f"{DENIED_IP}/32"])

        assert (await _request(app, api_key=a_key, peer_ip=ALLOWED_IP)).status_code == 200
        assert (await _request(app, api_key=a_key, peer_ip=DENIED_IP)).status_code  == 403
        assert (await _request(app, api_key=b_key, peer_ip=DENIED_IP)).status_code  == 200
        assert (await _request(app, api_key=b_key, peer_ip=ALLOWED_IP)).status_code == 403


# ── The refusal is readable by the caller it is sent to ───────────────────────

class TestDenialEnvelope:

    @pytest.mark.asyncio
    async def test_the_proxy_refusal_is_shaped_for_an_openai_client(self, app, test_db):
        """
        Proxy callers are OpenAI client libraries, which parse the body before
        the status. A refusal in the standard envelope raises inside the library
        rather than surfacing as a 403 the caller can act on.
        """
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(
            app, api_key=raw, peer_ip=DENIED_IP, path="/v1/chat/completions",
            json_body={"model": "openai/gpt-4o",
                       "messages": [{"role": "user", "content": "hi"}]},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "IP_NOT_ALLOWED"
        assert body["error"]["type"] == "forbidden"
        assert resp.headers.get("X-WrapSec-Trace-Id")

    @pytest.mark.asyncio
    async def test_every_other_refusal_uses_the_standard_envelope(self, app, test_db):
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(app, api_key=raw, peer_ip=DENIED_IP)
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "IP_NOT_ALLOWED"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path,body", [
        ("/v1/ai/request",       {"input": "hello"}),
        ("/v1/ai/scan-batch",    {"items": [{"input": "hello"}]}),
        ("/v1/chat/completions", {"model": "openai/gpt-4o",
                                  "messages": [{"role": "user", "content": "hi"}]}),
    ])
    async def test_one_code_identifies_the_denial_wherever_it_happens(
        self, app, test_db, path, body,
    ):
        """
        The shape differs by protocol; the code must not. An alert keyed on the
        code has to fire for this denial on every route, or its author learns
        the wrong lesson: that the restriction only applies where their rule
        happened to match.
        """
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        resp = await _request(app, api_key=raw, peer_ip=DENIED_IP, path=path,
                              json_body=body)
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "IP_NOT_ALLOWED", (
            f"{path} identifies the denial differently"
        )

    @pytest.mark.asyncio
    async def test_it_is_not_the_generic_permission_failure(self, app, test_db, auth_setup, auth_client):
        """
        Refused for WHERE you are is a different event from refused for WHO you
        are. Sharing FORBIDDEN with every RBAC denial would bury the first in
        the second.
        """
        raw, _ = await _seed_key(test_db, [ALLOWED_NET])
        denied = await _request(app, api_key=raw, peer_ip=DENIED_IP)

        # a genuine permission failure, for contrast
        forbidden = await auth_client.post(
            "/v1/keys",
            headers={"Authorization": f"Bearer {auth_setup['viewer_token']}"},
            json={"name": "x", "dept_id": str(auth_setup["dept"].id)},
        )

        assert denied.json()["error"]["code"] == "IP_NOT_ALLOWED"
        assert forbidden.status_code == 403
        assert forbidden.json()["error"]["code"] != "IP_NOT_ALLOWED"

    @pytest.mark.asyncio
    async def test_the_refusal_does_not_disclose_the_permitted_networks(self, app, test_db):
        """
        Whoever holds the key is not necessarily whoever may know the network
        layout. A refusal that names what would be accepted hands an attacker
        the shape of the target.
        """
        raw, _ = await _seed_key(test_db, [ALLOWED_NET, "10.0.0.0/8"])
        resp = await _request(app, api_key=raw, peer_ip=DENIED_IP)
        assert ALLOWED_NET not in resp.text
        assert "10.0.0.0" not in resp.text


# ── The fan-out charges the bucket the limiter enforces ───────────────────────

class TestRateLimitAccounting:
    """
    A multi-input scan charges its extra units against a bucket. The only thing
    that matters is that it is the SAME bucket the limiter enforces on.

    This was wrong, and the tests that covered it could not see the difference:
    they mocked the store and asserted it was CALLED with the right cost, which
    is true whichever bucket the units land in. So the assertion here is not
    about the call but about the identifier, compared against the one the
    enforcing middleware computed for the very same request.
    """

    @staticmethod
    def _canonical(raw_key: str) -> str:
        """The identifier the limiter buckets on, derived independently here."""
        return "key:" + hashlib.sha256(raw_key.encode()).hexdigest()[:16]

    @pytest.mark.asyncio
    async def test_extra_units_land_in_the_enforced_bucket(self, app, test_db, monkeypatch):
        from unittest.mock import AsyncMock, patch

        monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
        get_settings.cache_clear()
        try:
            raw, _ = await _seed_key(test_db, None)

            calls = []

            async def _spy(identifier, *args, **kwargs):
                calls.append({"id": identifier, "cost": kwargs.get("cost", 1)})
                return (False, 100, 0)

            with patch("cache.rate_limit_store.is_rate_limited", new=AsyncMock(side_effect=_spy)):
                resp = await _request(
                    app, api_key=raw, peer_ip=ALLOWED_IP,
                    path="/v1/ai/scan-batch",
                    json_body={"items": [{"input": "one"}, {"input": "two"},
                                         {"input": "three"}]},
                )

            assert resp.status_code == 200, resp.text
            assert len(calls) >= 2, (
                "expected the limiter's own check and the fan-out's charge; "
                f"saw {calls}"
            )

            buckets = {c["id"] for c in calls}
            assert len(buckets) == 1, (
                f"the fan-out charged a different bucket than the limiter enforces: {buckets}"
            )
            assert buckets == {self._canonical(raw)}, (
                f"not the canonical bucket: {buckets}"
            )

            # and the extra units really were the extra ones
            assert max(c["cost"] for c in calls) == 2, calls
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_the_charged_bucket_is_not_derived_from_the_key_record(
        self, app, test_db, monkeypatch,
    ):
        """
        The specific shape of the old defect: an identifier built from
        request.state.key_id, which is the key RECORD's id and already prefixed,
        giving "key:key_...". Nothing reads that bucket, so the fan-out was
        unmetered while appearing to charge.
        """
        from unittest.mock import AsyncMock, patch

        monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
        get_settings.cache_clear()
        try:
            raw, _ = await _seed_key(test_db, None)
            seen = []

            async def _spy(identifier, *args, **kwargs):
                seen.append(identifier)
                return (False, 100, 0)

            with patch("cache.rate_limit_store.is_rate_limited", new=AsyncMock(side_effect=_spy)):
                await _request(
                    app, api_key=raw, peer_ip=ALLOWED_IP, path="/v1/ai/scan-batch",
                    json_body={"items": [{"input": "a"}, {"input": "b"}]},
                )

            for identifier in seen:
                assert not identifier.startswith("key:key"), (
                    f"double-prefixed bucket: {identifier}"
                )
                assert "key_" not in identifier, (
                    f"bucket derived from the key record id: {identifier}"
                )
        finally:
            get_settings.cache_clear()
