# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
H8: Idempotency-Key must be scoped by principal.

An Idempotency-Key is a client-chosen string. Two different callers can
easily pick the same value ("retry-1"). If the middleware caches responses
by that raw string alone, tenant A's second request would return tenant B's
cached response - a cross-tenant data leak.

The middleware already prefixes the redis key with request.state.key_id.
These tests pin that behaviour so the scoping cannot regress.
"""


import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from api.v1.middleware import idempotency as idem_module
from api.v1.middleware.idempotency import IdempotencyMiddleware


class _FakeRedis:
    """Minimal in-memory redis substitute covering the three calls the
    idempotency middleware makes: set(..., nx=True, ex=...), get, setex."""

    def __init__(self):
        self.store: dict[str, str] = {}
        # ordered log of every write - lets tests assert scoping directly
        # instead of relying only on end-to-end response behaviour.
        self.writes: list[str] = []

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> bool:
        if nx and key in self.store:
            return False
        self.store[key] = value
        self.writes.append(key)
        return True

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.store[key] = value
        self.writes.append(key)


class _InjectKeyIdMiddleware(BaseHTTPMiddleware):
    """
    Test scaffold that populates request.state.key_id from a request header
    so tests can simulate different authenticated principals without booting
    the real auth middleware.
    """

    async def dispatch(self, request, call_next):
        request.state.key_id  = request.headers.get("x-test-key-id")
        request.state.trace_id = "test-trace"
        return await call_next(request)


async def _echo(request):
    body = await request.body()
    return JSONResponse({"echo": body.decode() or "empty"})


def _build_app() -> Starlette:
    # Starlette middleware order: first item is outermost. _InjectKeyIdMiddleware
    # must sit outside IdempotencyMiddleware so request.state.key_id is populated
    # by the time IdempotencyMiddleware inspects it.
    return Starlette(
        routes = [Route("/v1/ai/request", _echo, methods=["POST"])],
        middleware = [
            Middleware(_InjectKeyIdMiddleware),
            Middleware(IdempotencyMiddleware),
        ],
    )


@pytest.fixture
def fake_redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(idem_module, "get_redis", lambda: fake)
    return fake


@pytest.mark.asyncio
async def test_same_idempotency_key_different_principals_are_isolated(fake_redis):
    """Principal A caches a response. Principal B with the same
    Idempotency-Key must NOT get A's response back."""
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Principal A first request - primes the cache.
        r1 = await client.post(
            "/v1/ai/request",
            content = "hello-from-A",
            headers = {"Idempotency-Key": "shared-key", "x-test-key-id": "key:tenant-a"},
        )
        assert r1.status_code == 200
        assert r1.json() == {"echo": "hello-from-A"}

        # Principal A repeat -> hits cache. Must return A's body.
        r1_replay = await client.post(
            "/v1/ai/request",
            content = "hello-from-A",
            headers = {"Idempotency-Key": "shared-key", "x-test-key-id": "key:tenant-a"},
        )
        assert r1_replay.status_code == 200
        assert r1_replay.json() == {"echo": "hello-from-A"}
        assert r1_replay.headers.get("X-Idempotency-Replayed") == "true"

        # Principal B reusing the SAME Idempotency-Key value with a
        # DIFFERENT body. This must succeed as a fresh request, not collide
        # with A's cached response and not return 409.
        r2 = await client.post(
            "/v1/ai/request",
            content = "hello-from-B",
            headers = {"Idempotency-Key": "shared-key", "x-test-key-id": "key:tenant-b"},
        )
        assert r2.status_code == 200
        assert r2.json() == {"echo": "hello-from-B"}
        assert r2.headers.get("X-Idempotency-Replayed") is None


@pytest.mark.asyncio
async def test_redis_keys_include_principal_scope(fake_redis):
    """Confirms the underlying redis key is scoped by principal id.
    Guards against a refactor that drops the key_id prefix."""
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/v1/ai/request",
            content = "payload-a",
            headers = {"Idempotency-Key": "shared-key", "x-test-key-id": "key:tenant-a"},
        )
        await client.post(
            "/v1/ai/request",
            content = "payload-b",
            headers = {"Idempotency-Key": "shared-key", "x-test-key-id": "key:tenant-b"},
        )

    # Each principal produced its own :hash and :resp entries.
    assert len(fake_redis.store) == 4
    hash_keys = [k for k in fake_redis.store if k.endswith(":hash")]
    resp_keys = [k for k in fake_redis.store if k.endswith(":resp")]
    assert len(hash_keys) == 2
    assert len(resp_keys) == 2
    # And the hash-key values differ - proving distinct scoped hashes, not
    # a lucky ordering.
    assert hash_keys[0] != hash_keys[1]


@pytest.mark.asyncio
async def test_missing_principal_skips_idempotency(fake_redis):
    """Without a resolved principal, the middleware refuses to cache -
    scoping is impossible so we must not fall back to an unscoped key."""
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post(
            "/v1/ai/request",
            content = "anon",
            headers = {"Idempotency-Key": "shared-key"},
            # no x-test-key-id -> _InjectKeyIdMiddleware leaves state.key_id = None
        )
        assert r.status_code == 200
        assert r.json() == {"echo": "anon"}
    # Nothing was written to redis - no unscoped bucket exists.
    assert fake_redis.store == {}


@pytest.mark.asyncio
async def test_same_principal_conflict_returns_409(fake_redis):
    """Same Idempotency-Key + different body from same principal is a
    genuine client bug and must return 409."""
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r1 = await client.post(
            "/v1/ai/request",
            content = "first-body",
            headers = {"Idempotency-Key": "same-key", "x-test-key-id": "key:tenant-a"},
        )
        assert r1.status_code == 200

        r2 = await client.post(
            "/v1/ai/request",
            content = "different-body",
            headers = {"Idempotency-Key": "same-key", "x-test-key-id": "key:tenant-a"},
        )
        assert r2.status_code == 409
        assert r2.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
