# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Every route that DOCUMENTS a 401 must actually answer 401 without credentials.

Section 25 asks that each family's documented errors be exercised over real
HTTP. A run of the tier recording every response showed 401 was the largest
gap: 20 of the 28 published operations declare it and nothing triggered it.
Testing that route by route would be twenty near-identical tests, so this is
driven by the published artifact instead -- a route that GAINS a 401
declaration is covered the moment it does.

It is also a security guard, which is the better reason to keep it. A route
that quietly stops requiring credentials still passes every schema check in
this repository: the artifact would go on advertising the 401 while the runtime
served the body to anyone. The failure this catches is that gap opening.

The health probes are deliberately outside it. They declare no 401 because they
answer without credentials on purpose, and the artifact is what says so.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_SCHEMA = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def _routes_declaring_401() -> list[tuple[str, str]]:
    doc = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    return sorted(
        (method.upper(), path)
        for path, ops in doc.get("paths", {}).items()
        for method, op in ops.items()
        if method.lower() in {"get", "post", "put", "patch", "delete"}
        and "401" in op.get("responses", {})
    )


_DECLARED_401 = _routes_declaring_401()

# Path parameters are irrelevant here: the credential check runs before the
# route resolves its arguments, so any syntactically valid value reaches the
# same rejection.
_PLACEHOLDERS = {
    "{trace_id}": "req_00000000000000000000000000000000",
    "{run_id}":   "run-placeholder",
    "{key_id}":   "00000000-0000-0000-0000-000000000000",
}


def _concrete(path: str) -> str:
    for token, value in _PLACEHOLDERS.items():
        path = path.replace(token, value)
    return path


def test_the_artifact_still_declares_the_challenges_this_sweeps():
    """Without this the sweep could pass by iterating an empty list."""
    assert len(_DECLARED_401) >= 20, (
        f"only {len(_DECLARED_401)} published operations declare a 401; the "
        "sweep below has lost most of its surface"
    )
    assert not [p for _m, p in _DECLARED_401 if p.startswith("/health/live")], (
        "a health probe now declares a 401; it is meant to answer without "
        "credentials, so either the declaration or the route is wrong"
    )


@pytest.mark.parametrize("method,path", _DECLARED_401)
@pytest.mark.asyncio
async def test_a_route_that_documents_a_401_answers_one_without_credentials(
    client, method, path,
):
    """No credentials at all -- not a wrong one. A rejected credential and a
    missing one can take different paths, and the missing one is what an
    unauthenticated caller actually sends."""
    r = await client.request(method, _concrete(path))

    assert r.status_code == 401, (
        f"{method} {path} documents a 401 but answered {r.status_code} to a "
        "request carrying no credentials"
    )
