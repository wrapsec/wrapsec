# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""One source address cannot buy unlimited budget by varying a header.

The rate limiter runs BEFORE authentication, so the `x-api-key` it buckets on
has not been validated. It used to choose ONE bucket: per-key when the header
was present, per-address otherwise. A caller sending a different arbitrary value
each time therefore got a fresh per-key bucket per request and the address
bucket was never charged -- the per-address limit was not weakened, it was
absent, and every one of those requests still cost a Redis round trip and an
indexed credential lookup.

Both buckets are now charged. The address bucket carries its own, higher limit:
it exists to bound what one address can cost, not to throttle a tenant whose
traffic leaves through a single egress address.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

_PATH = "/v1/ai/request"
_BODY = {"input": "rate limit bucket identity check"}


async def _request(app, *, peer_ip: str, api_key: str | None):
    """A request whose PEER address is `peer_ip`.

    On the scope rather than in a header: a header is the thing a caller
    controls, and the control under test must not believe it.
    """
    headers = {"x-api-key": api_key} if api_key is not None else {}
    transport = ASGITransport(app=app, client=(peer_ip, 44444))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(_PATH, headers=headers, json=_BODY)


@pytest.fixture
def app():
    from api.main import app as application

    return application


@pytest.fixture
def low_source_limit(monkeypatch):
    """Shrink the address limit so the test does not have to send 600 requests.

    The limit's VALUE is configuration; what is under test is whether the bucket
    is charged at all.
    """
    from config.settings import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("RATE_LIMIT_PER_IP_PER_MINUTE", "5")
    get_settings.cache_clear()
    yield 5
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rotating_an_invalid_key_header_cannot_evade_the_address_limit(
    app, test_db, low_source_limit,
):
    """The reported bypass. Every request carries a DIFFERENT invalid key, so
    before the fix each one landed in its own fresh bucket and nothing was ever
    refused."""
    peer = "203.0.113.41"

    statuses = []
    for _ in range(low_source_limit + 3):
        resp = await _request(app, peer_ip=peer, api_key=f"wsk_live_{uuid.uuid4().hex}")
        statuses.append(resp.status_code)

    assert 429 in statuses, (
        "a single address sent more requests than the per-address limit, each "
        "with a different unvalidated key header, and none was refused: the "
        "address bucket is not being charged when a key header is present"
    )


@pytest.mark.asyncio
async def test_the_same_address_is_still_limited_without_any_key_header(
    app, test_db, low_source_limit,
):
    """The control for the bucket's identity: with no header at all the address
    must still be charged, which is the behaviour that already existed."""
    peer = "203.0.113.42"

    statuses = [
        (await _request(app, peer_ip=peer, api_key=None)).status_code
        for _ in range(low_source_limit + 3)
    ]

    assert 429 in statuses


@pytest.mark.asyncio
async def test_a_different_address_has_its_own_budget(app, test_db, low_source_limit):
    """Proves the bucket is keyed on the address and not global -- without this,
    a limiter that refused everything would satisfy the tests above."""
    exhausted = "203.0.113.43"
    for _ in range(low_source_limit + 3):
        await _request(app, peer_ip=exhausted, api_key=None)

    fresh = await _request(app, peer_ip="203.0.113.44", api_key=None)

    assert fresh.status_code != 429, (
        "a second address was refused on its first request, so the bucket is "
        "not per-address"
    )


@pytest.mark.asyncio
async def test_the_two_buckets_use_separate_keyspaces(app, test_db):
    """The address bucket and the per-key bucket are charged for the SAME
    request. If they shared a key they would consume each other, and the
    per-address limit would then depend on whether a key header happened to be
    present -- which is the defect, re-created by a different route."""
    from cache.redis_client import get_redis

    redis = get_redis()
    await redis.delete(*(await redis.keys("rate_limit:*")) or ["_noop_"])

    await _request(app, peer_ip="203.0.113.45", api_key=f"wsk_live_{uuid.uuid4().hex}")

    keys = {k.decode() if isinstance(k, bytes) else k for k in await redis.keys("rate_limit:*")}
    assert any(k.startswith("rate_limit:src:") for k in keys), (
        f"no per-address bucket was charged; buckets seen: {sorted(keys)}"
    )
    assert any(k.startswith("rate_limit:key:") for k in keys), (
        f"no per-key bucket was charged; buckets seen: {sorted(keys)}"
    )
