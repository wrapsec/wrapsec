# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The two lists an operator reads before confining a credential to a network.

Setting a source restriction from memory is how production gets locked out, so
the endpoint exists to replace memory with evidence: addresses the credential
actually authenticated from, and addresses it was refused from.

The failure worth guarding against is silent. The two source tables record the
credential in different formats -- the request trail keeps the prefixed form
that request state carries, the credential log keeps the bare id so it joins the
key table -- and querying one with the other's format returns an empty list
rather than an error. An empty list reads as "this key has never been used",
which is exactly the answer that makes an operator confident enough to save a
restriction that locks out production. So both lists are asserted to be
populated from rows written in the format each table really uses.
"""

import uuid
from datetime import timedelta

import pytest

from services.time import utc_now


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


async def _make_key(auth_client, auth_setup, name="observed"):
    resp = await auth_client.post(
        "/v1/keys",
        headers=_bearer(auth_setup["admin_token"]),
        json={"name": name, "dept_id": str(auth_setup["dept"].id)},
    )
    assert resp.status_code in (200, 201), resp.text
    return resp.json()["key_id"]


async def _seed_use(test_db, tenant_id, key_id, ip, *, days_ago=0, count=1):
    """A request the credential made, as the request trail stores it."""
    from db.models import AuditLogModel

    for _ in range(count):
        test_db.add(AuditLogModel(
            id             = uuid.uuid4(),
            tenant_id      = str(tenant_id),
            key_id         = f"key:{key_id}",          # prefixed, as stored
            trace_id       = f"tr_{uuid.uuid4().hex}",
            decision       = "ALLOW",
            risk_score     = 0.0,
            input_hash     = "h",
            detection_mode = "fast",
            execution_mode = "scan",
            latency_ms     = 1.0,
            ip_address     = ip,
            created_at     = utc_now() - timedelta(days=days_ago),
        ))
    await test_db.commit()


async def _seed_denial(test_db, tenant_id, key_id, ip, *, days_ago=0, count=1):
    """A refusal, as the credential log stores it."""
    from db.models import AuthEventModel

    for _ in range(count):
        test_db.add(AuthEventModel(
            id             = uuid.uuid4(),
            tenant_id      = tenant_id,
            key_id         = key_id,                   # bare, as stored
            action         = "api_key_ip_denied",
            success        = False,
            failure_reason = "ip_not_allowed",
            ip_address     = ip,
            created_at     = utc_now() - timedelta(days=days_ago),
        ))
    await test_db.commit()


class TestObservedAndDeniedAddresses:

    @pytest.mark.asyncio
    async def test_it_reads_both_tables_in_the_format_each_one_uses(
        self, auth_client, auth_setup, test_db,
    ):
        """
        The regression that matters: swap either format and the list this proves
        is populated becomes empty, with no error to notice.
        """
        key_id    = await _make_key(auth_client, auth_setup)
        tenant_id = auth_setup["tenant"].id

        await _seed_use(test_db, tenant_id, key_id, "203.0.113.10")
        await _seed_denial(test_db, tenant_id, key_id, "198.51.100.4")

        resp = await auth_client.get(
            f"/v1/keys/{key_id}/addresses",
            headers=_bearer(auth_setup["admin_token"]),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        assert [r["ip_address"] for r in body["observed"]] == ["203.0.113.10"]
        assert [r["ip_address"] for r in body["denied"]]   == ["198.51.100.4"]

    @pytest.mark.asyncio
    async def test_repeated_use_of_one_address_is_a_single_entry(
        self, auth_client, auth_setup, test_db,
    ):
        """
        A busy credential produces thousands of rows from a handful of
        addresses. The operator needs the handful; a list that repeats one
        address is a list nobody reads to the end.
        """
        key_id = await _make_key(auth_client, auth_setup)
        await _seed_use(test_db, auth_setup["tenant"].id, key_id, "203.0.113.10", count=3)

        resp = await auth_client.get(
            f"/v1/keys/{key_id}/addresses",
            headers=_bearer(auth_setup["admin_token"]),
        )
        observed = resp.json()["observed"]

        assert len(observed) == 1
        assert observed[0]["count"] == 3
        assert observed[0]["last_seen"].endswith("Z")

    @pytest.mark.asyncio
    async def test_it_does_not_report_another_credential_s_addresses(
        self, auth_client, auth_setup, test_db,
    ):
        """
        Attributing one key's traffic to another would have the operator allow a
        network this credential never uses, widening the restriction instead of
        tightening it.
        """
        mine    = await _make_key(auth_client, auth_setup, "mine")
        another = await _make_key(auth_client, auth_setup, "another")
        tenant  = auth_setup["tenant"].id

        await _seed_use(test_db, tenant, another, "203.0.113.99")
        await _seed_denial(test_db, tenant, another, "203.0.113.98")

        resp = await auth_client.get(
            f"/v1/keys/{mine}/addresses",
            headers=_bearer(auth_setup["admin_token"]),
        )
        body = resp.json()
        assert body["observed"] == []
        assert body["denied"]   == []

    @pytest.mark.asyncio
    async def test_it_looks_no_further_back_than_asked(
        self, auth_client, auth_setup, test_db,
    ):
        """
        An address a credential stopped using a year ago is not evidence about
        where it runs now, and allowing it re-opens a network that was retired.
        """
        key_id = await _make_key(auth_client, auth_setup)
        tenant = auth_setup["tenant"].id

        await _seed_use(test_db, tenant, key_id, "203.0.113.1", days_ago=1)
        await _seed_use(test_db, tenant, key_id, "203.0.113.2", days_ago=90)

        resp = await auth_client.get(
            f"/v1/keys/{key_id}/addresses?days=7",
            headers=_bearer(auth_setup["admin_token"]),
        )
        body = resp.json()

        assert body["window_days"] == 7
        assert [r["ip_address"] for r in body["observed"]] == ["203.0.113.1"]

    @pytest.mark.asyncio
    async def test_an_unbounded_window_is_clamped_rather_than_honoured(
        self, auth_client, auth_setup,
    ):
        """A caller-supplied window cannot become an unbounded table scan."""
        key_id = await _make_key(auth_client, auth_setup)

        resp = await auth_client.get(
            f"/v1/keys/{key_id}/addresses?days=100000",
            headers=_bearer(auth_setup["admin_token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["window_days"] == 365

        resp = await auth_client.get(
            f"/v1/keys/{key_id}/addresses?days=0",
            headers=_bearer(auth_setup["admin_token"]),
        )
        assert resp.json()["window_days"] == 1


class TestWhoMaySeeThem:
    """
    Where an organisation's traffic originates is infrastructure detail. It is
    shown to whoever can already change the restriction, and to nobody else.
    """

    @pytest.mark.asyncio
    async def test_a_viewer_is_refused(self, auth_client, auth_setup):
        key_id = await _make_key(auth_client, auth_setup)
        resp = await auth_client.get(
            f"/v1/keys/{key_id}/addresses",
            headers=_bearer(auth_setup["viewer_token"]),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_a_developer_is_refused(self, auth_client, auth_setup):
        key_id = await _make_key(auth_client, auth_setup)
        resp = await auth_client.get(
            f"/v1/keys/{key_id}/addresses",
            headers=_bearer(auth_setup["dev_token"]),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_an_unauthenticated_caller_is_refused(self, auth_client, auth_setup):
        key_id = await _make_key(auth_client, auth_setup)
        resp = await auth_client.get(f"/v1/keys/{key_id}/addresses")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_a_revoked_credential_is_not_found(
        self, auth_client, auth_setup,
    ):
        """
        The lookup deliberately excludes revoked keys. Asserted here so that
        relaxing it to make this view work would fail loudly rather than quietly
        re-open every auth-adjacent path that shares the lookup.
        """
        key_id = await _make_key(auth_client, auth_setup)
        deleted = await auth_client.delete(
            f"/v1/keys/{key_id}", headers=_bearer(auth_setup["admin_token"]),
        )
        assert deleted.status_code in (200, 204), deleted.text

        resp = await auth_client.get(
            f"/v1/keys/{key_id}/addresses",
            headers=_bearer(auth_setup["admin_token"]),
        )
        assert resp.status_code == 404
