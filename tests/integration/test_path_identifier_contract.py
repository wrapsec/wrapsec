# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
A path identifier that cannot name a stored resource is refused as input.

THE DEFECT THIS PINS. A `%00` path segment used to travel intact to asyncpg,
which raises `CharacterNotInRepertoireError` ("invalid byte sequence for
encoding UTF8") in the middle of the query. No route handles it, so the caller
received `500 INTERNAL_ERROR` and the request's transaction was left aborted --
on three published operations, every one of which is a plain `GET` any
unauthenticated scanner will try.

WHAT IS ASSERTED, AND WHY A STATUS ASSERTION IS NOT ENOUGH. The failure mode is
"the value reached the database", and a body assertion cannot see that: a route
that still queried and then happened to answer 422 would pass. So each test
spies on the repository method the route actually calls and asserts it was NOT
invoked -- and the companion test asserts the SAME spy IS invoked for a
well-formed identifier, which is what stops the detector from being one that
passes because the spy was never wired up.

WHAT IS DELIBERATELY NOT CHANGED. An identifier that is merely unknown is not a
malformed one, and the two keep their separate answers:

    GET /v1/ai/requests/{trace_id}          unknown -> 404
    GET /v1/proxy/interactions/{trace_id}   unknown -> 404
    GET /v1/agent-runs/{run_id}             unknown -> 200, empty timeline

Those three differ from each other, which is why the fix does not translate a
malformed identifier into "not found": doing so would have to pick one of the
three, and would make the run route claim a malformed id is a real run with no
turns.

Scoping is NOT re-tested here. `test_api_proxy_interactions.py` and the audit
suites cover it and still pass, which is the evidence that this pass did not
touch authorization.
"""

from __future__ import annotations

import pytest

# `%00` alone and a NUL embedded in an otherwise plausible identifier. The second
# matters because a caller can reach the same driver error without the segment
# looking suspicious.
_MALFORMED = ["%00", "req_a%00b"]

# Well-formed, and chosen so it cannot exist: the lookup runs and finds nothing.
_ABSENT = "req_00000000000000000000000000000000"

# (route template, repository class path, method name) for each published
# operation that takes a path identifier. Pinned per route rather than proved
# once, because they do not share a lookup -- each reaches the database through
# its own repository call.
_ROUTES = [
    ("/v1/ai/requests/{}", "db.repositories.audit.AuditRepository", "get_by_trace_id"),
    ("/v1/agent-runs/{}", "db.repositories.audit.AuditRepository", "list_run"),
    ("/v1/proxy/interactions/{}", "db.repositories.proxy_interaction.ProxyInteractionRepository",
     "get_by_trace_id"),
]

_CANONICAL_ERROR_FIELDS = {"code", "severity", "key", "params", "message", "trace_id",
                           "invalid_params"}


def _spy(monkeypatch, dotted: str, method: str) -> list:
    """Record calls to one repository method without changing what it does."""
    module_path, _, cls_name = dotted.rpartition(".")
    module = __import__(module_path, fromlist=[cls_name])
    cls = getattr(module, cls_name)
    original = getattr(cls, method)
    calls: list = []

    async def recording(self, *args, **kwargs):
        calls.append((args, kwargs))
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(cls, method, recording)
    return calls


@pytest.mark.parametrize("template,repo,method", _ROUTES)
@pytest.mark.parametrize("bad", _MALFORMED)
@pytest.mark.asyncio
async def test_a_malformed_identifier_never_reaches_the_database(
    client, admin_headers, monkeypatch, template, repo, method, bad,
):
    calls = _spy(monkeypatch, repo, method)

    r = await client.get(template.format(bad), headers=admin_headers)

    assert r.status_code == 422, r.text
    assert calls == [], (
        f"{repo}.{method} was called with a malformed identifier, so the value "
        "still reaches the driver and the 422 is only hiding it"
    )


@pytest.mark.parametrize("template,repo,method", _ROUTES)
@pytest.mark.asyncio
async def test_the_spy_sees_a_well_formed_identifier(
    client, admin_headers, monkeypatch, template, repo, method,
):
    """The control for the test above.

    Without this, a spy patched onto the wrong attribute would record nothing for
    either input and the not-called assertion would pass no matter what the route
    did.
    """
    calls = _spy(monkeypatch, repo, method)

    await client.get(template.format(_ABSENT), headers=admin_headers)

    assert calls, f"{repo}.{method} was never called, so the spy proves nothing"


@pytest.mark.parametrize("template,repo,method", _ROUTES)
@pytest.mark.parametrize("bad", _MALFORMED)
@pytest.mark.asyncio
async def test_the_refusal_is_the_canonical_envelope(
    client, admin_headers, template, repo, method, bad,
):
    r = await client.get(template.format(bad), headers=admin_headers)

    assert r.status_code == 422, r.text
    body = r.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert set(error) <= _CANONICAL_ERROR_FIELDS, f"unexpected fields: {sorted(error)}"
    assert error["code"]     == "VALIDATION_ERROR"
    assert error["key"]      == "errors.VALIDATION_ERROR"
    assert error["severity"] == "WARNING"
    assert error["trace_id"].startswith("req_")

    # The refusal names the path parameter, which is what makes it actionable --
    # a caller learns WHICH value was rejected without the message spelling it out.
    entries = error["invalid_params"]
    assert len(entries) == 1, entries
    entry = entries[0]
    assert set(entry) == {"field", "code", "key", "params"}
    assert entry["field"] in {"trace_id", "run_id"}
    assert entry["code"] == "INVALID_VALUE"
    assert entry["key"] == "forms.errors.INVALID_VALUE"


@pytest.mark.parametrize("template,repo,method", _ROUTES)
@pytest.mark.parametrize("bad", _MALFORMED)
@pytest.mark.asyncio
async def test_the_refusal_leaks_no_driver_or_storage_detail(
    client, admin_headers, template, repo, method, bad,
):
    """The 500 this replaces logged a full traceback and the SQL. None of that
    was ever serialized, and none of it may start being serialized now."""
    r = await client.get(template.format(bad), headers=admin_headers)

    assert r.status_code == 422
    lowered = r.text.lower()
    for term in ("characternotinrepertoire", "asyncpg", "dbapi", "sqlalchemy", "postgres",
                 "select ", "audit_logs", "proxy_interactions", "traceback", "/home/",
                 "encoding", "byte sequence", "repertoire"):
        assert term not in lowered, f"the refusal carried {term!r}"
    # The rejected value is not echoed either: reflecting a caller's probe back is
    # what the envelope's user/debug split exists to prevent.
    assert "\x00" not in r.text


# -- the behaviour that must NOT change ---------------------------------------

@pytest.mark.asyncio
async def test_an_unknown_scan_trace_is_still_a_404(client, admin_headers):
    r = await client.get(f"/v1/ai/requests/{_ABSENT}", headers=admin_headers)
    assert r.status_code == 404, r.text
    assert r.json()["error"]["code"] == "NOT_FOUND"
    assert r.json()["error"]["params"] == {"resource": "request"}


@pytest.mark.asyncio
async def test_an_unknown_interaction_is_still_a_404(client, admin_headers):
    r = await client.get(f"/v1/proxy/interactions/{_ABSENT}", headers=admin_headers)
    assert r.status_code == 404, r.text
    assert r.json()["error"]["code"] == "NOT_FOUND"
    assert r.json()["error"]["params"] == {"resource": "interaction"}


@pytest.mark.asyncio
async def test_an_unknown_run_is_still_an_empty_timeline(client, admin_headers):
    """Not a 404, and deliberately so -- the run route answers an unknown id with
    an empty timeline so a caller cannot use it to learn which run_ids exist in
    other tenants. A malformed id must not be folded into that answer either."""
    r = await client.get(f"/v1/agent-runs/{_ABSENT}", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["scans"] == []


@pytest.mark.asyncio
async def test_an_ordinary_identifier_is_not_rejected_by_the_constraint(client, admin_headers):
    """The constraint forbids exactly one byte. Everything else a caller might
    put in a path segment -- including characters that look hostile -- still
    reaches the lookup and answers normally."""
    # Values that stay inside ONE path segment. A traversal like `../etc/passwd`
    # is normalized by the client into a different path before the app sees it,
    # so it would test the router, not this constraint.
    for value in ("req_" + "a" * 32, "run-1", "a b", "%7Bbraces%7D", "ünïcode",
                  "a'b", "a;b", "%25", "a%0Ab"):
        r = await client.get(f"/v1/agent-runs/{value}", headers=admin_headers)
        assert r.status_code == 200, f"{value!r} was refused: {r.text}"
