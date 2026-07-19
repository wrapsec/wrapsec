# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression tests for SecurityHeadersMiddleware (pentest M3).
Verifies every locked-down header lands on a normal 2xx response, on a
5xx exception path, and that a downstream handler can override any single
header without losing the rest.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from api.v1.middleware.security_headers import (
    SecurityHeadersMiddleware,
    _SECURITY_HEADERS,
)


async def _ok(_request):
    return JSONResponse({"ok": True})


async def _boom(_request):
    # 5xx modelled as HTTPException so Starlette's ExceptionMiddleware
    # converts it to a real 500 response that reaches our middleware.
    # In production, unhandled_exception_handler does the same thing.
    raise HTTPException(status_code=500, detail="kaboom")


async def _custom_csp(_request):
    r = JSONResponse({"ok": True})
    r.headers["Content-Security-Policy"] = "default-src 'self'"
    return r


def _build_app():
    return Starlette(
        debug  = False,
        routes = [
            Route("/ok",     _ok),
            Route("/boom",   _boom),
            Route("/custom", _custom_csp),
        ],
        middleware = [Middleware(SecurityHeadersMiddleware)],
    )


@pytest.mark.asyncio
async def test_all_headers_on_success():
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/ok")
    assert r.status_code == 200
    for name, value in _SECURITY_HEADERS.items():
        assert r.headers.get(name) == value, f"missing/wrong {name}"


@pytest.mark.asyncio
async def test_headers_on_server_error():
    app = _build_app()
    async with AsyncClient(
        transport = ASGITransport(app=app),
        base_url  = "http://test",
    ) as c:
        r = await c.get("/boom")
    assert r.status_code == 500
    for name in _SECURITY_HEADERS:
        assert name in r.headers, f"5xx path missing {name}"


@pytest.mark.asyncio
async def test_handler_override_preserved():
    """A handler-set CSP must win; other headers still applied."""
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/custom")
    assert r.headers.get("Content-Security-Policy") == "default-src 'self'"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains"
