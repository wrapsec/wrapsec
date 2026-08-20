# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
How an upstream failure reaches the caller.

Collapsing every provider failure into one status strips out the only thing the
caller can act on. A rate limit needs a backoff, a bad model name needs a fix in
the request, and a rejected credential is an operator problem rather than an
outage. These pin that each stays distinguishable, and that the provider's own
error text never reaches the caller.
"""

import httpx
import pytest

from api.v1.endpoints.proxy import _map_provider_failure


def _status_error(status: int, headers: dict | None = None, body: str = "provider detail"):
    request  = httpx.Request("POST", "https://provider.example/v1/chat/completions")
    response = httpx.Response(status, headers=headers or {}, text=body, request=request)
    return httpx.HTTPStatusError("upstream", request=request, response=response)


@pytest.mark.parametrize(
    "upstream,expected_status,expected_code",
    [
        (429, 429, "provider_rate_limited"),
        (401, 502, "provider_auth_failed"),
        (403, 502, "provider_auth_failed"),
        (404, 400, "provider_model_not_found"),
        (400, 400, "provider_rejected_request"),
        (422, 400, "provider_rejected_request"),
        (500, 502, "provider_unavailable"),
        (503, 502, "provider_unavailable"),
    ],
)
def test_each_provider_condition_maps_distinctly(upstream, expected_status, expected_code):
    status, code, _message, _retry = _map_provider_failure(_status_error(upstream))
    assert (status, code) == (expected_status, expected_code)


def test_a_connection_failure_is_reported_as_unreachable():
    exc = httpx.ConnectError("no route to host")
    status, code, _message, retry = _map_provider_failure(exc)
    assert (status, code, retry) == (502, "provider_unreachable", None)


def test_an_unmapped_status_falls_back_without_raising():
    status, code, _message, _retry = _map_provider_failure(_status_error(418))
    assert status == 502
    assert code   == "provider_unreachable"


def test_retry_after_is_passed_through_when_the_provider_sends_one():
    """A caller backing off should use the provider's guidance, not a guess."""
    _status, _code, _message, retry = _map_provider_failure(
        _status_error(429, headers={"Retry-After": "30"})
    )
    assert retry == "30"


def test_retry_after_is_absent_when_the_provider_omits_it():
    _status, _code, _message, retry = _map_provider_failure(_status_error(429))
    assert retry is None


@pytest.mark.parametrize("upstream", [400, 401, 404, 429, 500])
def test_the_provider_error_body_is_never_echoed(upstream):
    """
    Provider bodies can carry account identifiers and internal detail, so the
    caller gets a WrapSec message and the provider text goes to the log instead.
    """
    _status, _code, message, _retry = _map_provider_failure(
        _status_error(upstream, body="org_id=acct_12345 secret detail")
    )
    assert "acct_12345" not in message
    assert "secret detail" not in message
