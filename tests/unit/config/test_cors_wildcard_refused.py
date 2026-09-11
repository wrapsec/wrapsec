# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A wildcard CORS origin must not be configurable.

The application enables credentialed CORS whenever any origin is configured. A
wildcard therefore produces `allow_origins=["*"]` WITH `allow_credentials=True`,
and the comment that used to sit next to that code said browsers reject the
combination -- implying it was inert.

It is not inert, and `test_the_framework_reflects_a_wildcard_origin_with_credentials`
below measures that against the INSTALLED framework rather than asserting it: the
middleware echoes the caller's Origin and sets allow-credentials on it, so every
origin on the web would receive credentialed access.

That test is the reason the validator exists. Without it, someone reads the
validator, thinks the refusal is pedantry about a combination browsers reject
anyway, and relaxes it.
"""

from __future__ import annotations

import pytest

from config.settings import Settings

_REQUIRED = {"secret_key": "k" * 40, "admin_api_key": "a" * 40}


def test_a_wildcard_origin_is_refused_at_startup():
    with pytest.raises(ValueError, match=r"must not contain"):
        Settings(**_REQUIRED, cors_allowed_origins=["*"])


def test_a_wildcard_among_real_origins_is_also_refused():
    """The dangerous entry does not become safe by having company."""
    with pytest.raises(ValueError, match=r"must not contain"):
        Settings(**_REQUIRED, cors_allowed_origins=["https://dash.example.com", "*"])


def test_whitespace_does_not_smuggle_a_wildcard_past_the_check():
    with pytest.raises(ValueError, match=r"must not contain"):
        Settings(**_REQUIRED, cors_allowed_origins=[" * "])


def test_explicit_origins_and_an_empty_list_are_both_accepted():
    """The control. A validator that refused everything would satisfy the tests
    above and break every real deployment."""
    assert Settings(**_REQUIRED, cors_allowed_origins=[]).cors_allowed_origins == []
    assert Settings(
        **_REQUIRED, cors_allowed_origins=["https://dash.example.com"],
    ).cors_allowed_origins == ["https://dash.example.com"]


def test_the_framework_reflects_a_wildcard_origin_with_credentials():
    """Why the refusal is not pedantry -- measured, not assumed.

    If a future framework version really did reject the combination, this fails
    and the validator's justification can be revisited on evidence. Until then
    the wildcard is the worst available configuration, not a no-op.
    """
    from starlette.applications import Starlette
    from starlette.middleware.cors import CORSMiddleware
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    probe = Starlette(routes=[Route("/x", lambda r: PlainTextResponse("ok"))])
    probe.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_credentials=True,
        allow_methods=["*"], allow_headers=["*"],
    )

    response = TestClient(probe).get("/x", headers={"Origin": "https://attacker.example"})

    assert response.headers.get("access-control-allow-origin") == "https://attacker.example", (
        "the framework no longer reflects an arbitrary Origin under a wildcard"
    )
    assert response.headers.get("access-control-allow-credentials") == "true", (
        "the framework no longer sets allow-credentials under a wildcard"
    )
