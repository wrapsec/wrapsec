# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The schema document is authenticated in production and public everywhere else.

`/openapi.json` sat in the unconditional public-path allowlist, so the auth
middleware returned before asking for a credential -- in every environment.
Production disables the rendered docs (`api/main.py` passes `docs_url=None` and
`redoc_url=None`), which made the deployment look closed while the
machine-readable form of the same information stayed open, and that form
enumerates rather than mentions: every path, method, parameter, and error code.

These tests drive the real middleware rather than the predicate, because the
defect was in the boundary's ordering -- the early return -- not in any
environment check. A test of the helper alone would pass even if `dispatch`
never consulted it.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from api.v1.middleware.auth import AuthMiddleware
from config.settings import get_settings

_SCHEMA_PATH = "/openapi.json"


async def _schema(_request):
    """Stands in for the generated document; the middleware never reaches it
    when the request is refused, which is the whole point."""
    return JSONResponse({"openapi": "3.1.0", "paths": {"/v1/ai/request": {}}})


def _build_app() -> Starlette:
    return Starlette(
        routes     = [Route(_SCHEMA_PATH, _schema)],
        middleware = [Middleware(AuthMiddleware)],
    )


@pytest.fixture
def as_environment(monkeypatch):
    """Run the app under a given environment, with the settings cache honoured.

    `get_settings` is cached per process, so setting the variable alone changes
    nothing. Clearing on the way in AND out keeps the rest of the suite from
    inheriting whichever environment ran last.
    """
    def _set(name: str):
        monkeypatch.setenv("ENVIRONMENT", name)
        get_settings.cache_clear()
        assert get_settings().environment == name, "environment did not take effect"

    yield _set
    monkeypatch.undo()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_unauthenticated_openapi_is_refused_in_production(as_environment):
    """The regression: no credential, production, and the schema came back 200."""
    as_environment("production")

    async with AsyncClient(
        transport=ASGITransport(app=_build_app()), base_url="http://test"
    ) as client:
        response = await client.get(_SCHEMA_PATH)

    assert response.status_code == 401, (
        "the schema document was served to an unauthenticated caller in "
        "production; it describes the whole attack surface of the deployment"
    )
    # Refused by the ordinary auth boundary, so it reports like any other
    # unauthenticated request rather than through a bespoke path.
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    assert "openapi" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("environment", ["development", "staging"])
async def test_the_schema_stays_public_outside_production(as_environment, environment):
    """Local development and the test suite read it exactly as before.

    Both non-production values are covered: the setting is a closed set
    (`development`, `staging`, `production`), so these are the only two
    environments in which the document stays open.
    """
    as_environment(environment)

    async with AsyncClient(
        transport=ASGITransport(app=_build_app()), base_url="http://test"
    ) as client:
        response = await client.get(_SCHEMA_PATH)

    assert response.status_code == 200, (
        f"the schema must stay public in {environment!r}; protecting production "
        f"must not change local development"
    )
    assert response.json()["openapi"] == "3.1.0"


@pytest.mark.asyncio
async def test_an_authenticated_caller_still_receives_the_schema_in_production(
    as_environment,
):
    """Protected, not withdrawn.

    An integrator holding a credential may legitimately fetch the contract. If
    production returned 401 to everyone, the published surface would have been
    removed rather than secured, and the fix would be a breaking change wearing
    a security label.
    """
    as_environment("production")

    async with AsyncClient(
        transport=ASGITransport(app=_build_app()), base_url="http://test"
    ) as client:
        response = await client.get(
            _SCHEMA_PATH, headers={"x-api-key": get_settings().admin_api_key}
        )

    assert response.status_code == 200
    assert response.json()["openapi"] == "3.1.0"


def test_the_path_is_not_in_the_unconditional_allowlist():
    """Guards the shape of the fix, not only its effect.

    Returning the path to `PUBLIC_PATHS` would restore the defect while every
    behavioural test above still passed in a non-production run, which is the
    only way the suite normally executes.
    """
    from api.v1.middleware.auth import _NON_PRODUCTION_PUBLIC_PATHS, PUBLIC_PATHS

    assert _SCHEMA_PATH not in PUBLIC_PATHS, (
        "/openapi.json is unconditionally public again; it must be gated on "
        "the environment"
    )
    assert _SCHEMA_PATH in _NON_PRODUCTION_PUBLIC_PATHS


def test_an_unconfigured_deployment_is_treated_as_production():
    """A deployment that configures nothing must get the protected behaviour.

    The gate opens only on a value that is explicitly not production, so what
    the setting does in the ABSENCE of configuration decides whether the fix
    holds where it matters most: a hurried deployment that set no variables.

    Asserted on the field default rather than by building a Settings object.
    A developer checkout carries a `.env` setting `development`, so unsetting
    the process variable proves nothing about a deployment without that file --
    it just reads the checkout's. Constructing with `_env_file=None` instead
    drops every other required field and fails for an unrelated reason. The
    declared default is the thing that decides it.
    """
    from config.settings import Settings

    assert Settings.model_fields["environment"].default == "production", (
        "the environment default is no longer production; an unconfigured "
        "deployment would serve the schema document unauthenticated"
    )
