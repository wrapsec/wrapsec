# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A malformed credential is an authentication failure, never a server error.

Both credential checks compared str with `hmac.compare_digest`, which accepts
str only when BOTH sides are ASCII and raises TypeError otherwise. The presented
half is a request header, so an unauthenticated caller chose it: `x-api-key:
café` turned a credential check into an unhandled exception, answered 500 with a
traceback in the logs.

It failed in the safe direction -- nothing authenticated -- but an anonymous
caller could generate server errors and log volume at will, and a malformed
credential is a 401, not an internal error.

These drive the real routes, because the defect was in the middleware and the
metrics handler rather than in any helper.
"""

from __future__ import annotations

import pytest

# Sent as BYTES, which is how this reaches a server at all.
#
# HTTP header values are bytes on the wire, and the ASGI server decodes them as
# latin-1 -- so a byte above 0x7F becomes a str character above 0x7F, which is
# exactly what an ASCII-only comparison rejects. An http client will not encode
# a non-ASCII str INTO a header (httpx raises before sending), so passing a str
# here would test the client, not the server. Anything writing raw bytes to a
# socket has no such scruples.
_MALFORMED = [
    pytest.param("café".encode(),                  id="utf8-accent"),
    pytest.param(b"wsk_live_caf\xe9",              id="valid-prefix-then-high-byte"),
    pytest.param("ключ".encode(),                  id="utf8-cyrillic"),
    pytest.param("🔑".encode(),                    id="utf8-emoji"),
    pytest.param(b"\xff\xfe\xfd",                 id="not-valid-utf8"),
    pytest.param(("wsk_live_" + "é" * 40).encode(), id="long-accented"),
]


@pytest.mark.parametrize("credential", _MALFORMED)
@pytest.mark.asyncio
async def test_a_non_ascii_api_key_is_refused_not_a_server_error(client, credential):
    resp = await client.post(
        "/v1/ai/request", json={"input": "hello"}, headers={"x-api-key": credential},
    )

    assert resp.status_code == 401, (
        f"a malformed credential answered {resp.status_code}; an unauthenticated "
        "caller can choose this header, so anything but a 401 lets them pick the "
        "status code"
    )
    assert resp.status_code != 500


@pytest.mark.parametrize("credential", _MALFORMED)
@pytest.mark.asyncio
async def test_a_non_ascii_metrics_token_is_refused_not_a_server_error(client, credential):
    resp = await client.get("/metrics", headers={"Authorization": b"Bearer " + credential})

    assert resp.status_code == 401, (
        f"the metrics endpoint answered {resp.status_code} to a malformed token"
    )


@pytest.mark.asyncio
async def test_the_real_credentials_still_authenticate(client, admin_headers):
    """The control. A comparison that returned False unconditionally would
    satisfy every assertion above and lock everyone out."""
    resp = await client.post("/v1/ai/request", json={"input": "hello"}, headers=admin_headers)

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_a_wrong_ascii_credential_is_still_refused(client):
    """The other control: the fix must not make comparison permissive."""
    resp = await client.post(
        "/v1/ai/request", json={"input": "hello"},
        headers={"x-api-key": "wsk_live_definitely_not_the_admin_key"},
    )

    assert resp.status_code == 401
