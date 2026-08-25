# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
No published response schema may be one the runtime does not apply.

A FastAPI route can declare `response_model` and still return a constructed
`JSONResponse`. OpenAPI then advertises the model while the framework skips
validation and field filtering entirely, so the schema promises a shape nothing
enforces. That is worse than declaring nothing: a consumer trusts it, and an
undeclared field the model would have removed is served anyway.

`test_fastapi_filters_a_value_return_but_not_a_response_object` pins that premise
against the installed FastAPI rather than assuming it, because everything else
here is source inspection and would silently stop meaning anything if the
framework's behaviour changed.

WHAT THIS DOES NOT DO. It does not require every route to have a response model.
Most of this API returns constructed responses and declares no model, which is
honest: nothing is advertised, so nothing is unenforced. The invariant is
narrower and is the one that actually protects a consumer:

    a route may declare a response model, or it may return a Response object,
    but if it does both it must be a recorded exception.

RETURN ANALYSIS. Two mistakes make this kind of check report nonsense, and both
are handled:

  * a `return` inside a nested helper defined in the endpoint body is not the
    endpoint's return -- an earlier pass counted `_rows()` inside
    `get_key_addresses` and misread the route as returning a value;
  * a call to `error_response()` / `_reject()` / `_bad_request()` / `_set_status()`
    IS a Response return, because those helpers construct one. Reading only the
    literal `JSONResponse(` calls misses them and overstates enforcement.
"""

from __future__ import annotations

import ast
import inspect

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import BaseModel

_RESPONSE_CLASSES = {
    "JSONResponse", "Response", "StreamingResponse", "PlainTextResponse",
    "FileResponse", "RedirectResponse", "ORJSONResponse", "HTMLResponse",
}

# The frozen public API surface: the routes an SDK, the MCP adapter or a
# documented integrator calls. Everything else is operator, dashboard, setup or
# monitoring surface and is out of scope for this invariant.
PUBLIC_ROUTES: set[tuple[str, str]] = {
    ("/health", "GET"), ("/health/live", "GET"), ("/health/ready", "GET"),
    ("/health/config", "GET"),
    ("/v1/capabilities", "GET"),
    ("/v1/ai/request", "POST"), ("/v1/ai/scan-batch", "POST"),
    ("/v1/ai/requests/{trace_id}", "GET"), ("/v1/agent-runs/{run_id}", "GET"),
    ("/v1/audit/logs", "GET"), ("/v1/audit/stats", "GET"), ("/v1/audit/export", "GET"),
    ("/v1/proxy/interactions", "GET"), ("/v1/proxy/interactions/{trace_id}", "GET"),
    ("/v1/chat/completions", "POST"),
    ("/v1/keys", "GET"), ("/v1/keys", "POST"),
    ("/v1/settings/thresholds", "GET"), ("/v1/settings/thresholds", "PUT"),
    ("/v1/settings/layers", "GET"), ("/v1/settings/layers", "PUT"),
    ("/v1/settings/llm", "GET"), ("/v1/settings/llm", "PUT"),
    ("/v1/settings/rate_limit", "GET"), ("/v1/settings/rate_limit", "PUT"),
    ("/v1/settings/proxy", "GET"), ("/v1/settings/proxy", "PUT"),
    ("/v1/settings/proxy", "DELETE"),
}

# Routes allowed to declare a response model AND return a Response object, each
# with the reason. Empty today: nothing declares a model yet. An entry here is a
# statement that the schema is documentation only and the runtime does not apply
# it -- not a way to silence the check.
DOCUMENTATION_ONLY_EXCEPTIONS: dict[tuple[str, str], str] = {}

# Routes that will not receive an ordinary response model at all. Recorded so the
# reason survives, and so a later pass does not "complete" the coverage by
# converting them.
NON_MODEL_ROUTES: dict[tuple[str, str], str] = {
    ("/v1/audit/export", "GET"):
        "Returns CSV, not JSON. A response model describes a JSON body and would "
        "misdescribe this one; the media type is the contract here.",
    ("/v1/chat/completions", "POST"):
        "OpenAI-compatible. The success body is provider-shaped and passed "
        "through, and the route answers through many constructed Response paths "
        "including the OpenAI error envelope. Its compatibility contract is "
        "verified separately, not by a WrapSec response model.",
}


def _response_returning_helpers() -> set[str]:
    """Module-level helpers that construct a Response, so a call to one counts as
    a Response return."""
    import errors.response as errresp
    from api.v1.endpoints import proxy
    from api.v1.endpoints.admin import tenants

    names: set[str] = set()
    for module in (errresp, proxy, tenants):
        try:
            tree = ast.parse(inspect.getsource(module))
        except OSError:  # pragma: no cover - source always available in-tree
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            annotation = node.returns
            ann_name = (
                annotation.id if isinstance(annotation, ast.Name)
                else getattr(annotation, "attr", None)
            )
            if ann_name in _RESPONSE_CLASSES:
                names.add(node.name)
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Return) and isinstance(child.value, ast.Call):
                    fn = child.value.func
                    called = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
                    if called in _RESPONSE_CLASSES:
                        names.add(node.name)
                        break
    return names


_HELPERS = _response_returning_helpers()


def _own_returns(fndef: ast.AST) -> list[ast.Return]:
    """Return statements belonging to this function, excluding nested scopes."""
    found: list[ast.Return] = []

    def walk(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Return):
                found.append(child)
            walk(child)

    walk(fndef)
    return found


def _returns_a_response_object(endpoint) -> bool:
    """Whether any of the endpoint's own returns yields a Response object.

    Resolves three forms: a direct construction, a call to a Response-returning
    helper, and a name bound to a Response earlier in the function (the
    `response = JSONResponse(...); ...; return response` shape used by the auth
    routes).
    """
    try:
        source = inspect.getsource(endpoint)
    except OSError:  # pragma: no cover
        return False
    fndef = ast.parse(ast.unparse(ast.parse(source))).body[0]

    response_names = {
        target.id
        for node in ast.walk(fndef)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
        for target in node.targets
        if isinstance(target, ast.Name)
        and (
            (isinstance(node.value.func, ast.Name) and node.value.func.id in _RESPONSE_CLASSES)
            or getattr(node.value.func, "attr", "") in _RESPONSE_CLASSES
        )
    }

    for node in _own_returns(fndef):
        value = node.value
        if isinstance(value, ast.Call):
            fn = value.func
            called = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            if called in _RESPONSE_CLASSES or called in _HELPERS:
                return True
        elif isinstance(value, ast.Name) and value.id in response_names:
            return True
        elif isinstance(value, ast.Await):
            inner = value.value
            if isinstance(inner, ast.Call):
                fn = inner.func
                called = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
                if called in _HELPERS or called in _RESPONSE_CLASSES:
                    return True
    return False


def _public_routes():
    from api.main import app

    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods:
            if (route.path, method) in PUBLIC_ROUTES:
                yield route, method


# ── the premise, against the installed framework ─────────────────────────────

def test_fastapi_filters_a_value_return_but_not_a_response_object():
    """Everything else here is source inspection, and it only means something
    while this holds: a returned value is filtered through the model, a returned
    Response is not, and OpenAPI advertises the model either way."""
    class Model(BaseModel):
        kept: str

    probe = FastAPI()

    @probe.get("/value", response_model=Model)
    def _value():
        return {"kept": "a", "undeclared": "leaked"}

    @probe.get("/response", response_model=Model)
    def _response():
        return JSONResponse(content={"kept": "a", "undeclared": "leaked"})

    client = TestClient(probe)
    assert client.get("/value").json() == {"kept": "a"}
    assert client.get("/response").json() == {"kept": "a", "undeclared": "leaked"}

    spec = probe.openapi()
    for path in ("/value", "/response"):
        schema = spec["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        assert schema == {"$ref": "#/components/schemas/Model"}


# ── the invariant ────────────────────────────────────────────────────────────

def test_the_public_route_list_matches_the_application():
    """The surface is frozen; if a route is renamed or removed this list must be
    updated deliberately rather than silently covering fewer routes."""
    from api.main import app

    live = {(r.path, m) for r in app.routes if isinstance(r, APIRoute) for m in r.methods}
    missing = PUBLIC_ROUTES - live
    assert not missing, f"public routes that no longer exist: {sorted(missing)}"


def test_no_public_route_advertises_a_model_it_bypasses():
    """The invariant. A route may declare a model, or return a Response object,
    but doing both means OpenAPI promises a shape the runtime never applies."""
    offenders = []
    for route, method in _public_routes():
        if route.response_model is None:
            continue
        if (route.path, method) in DOCUMENTATION_ONLY_EXCEPTIONS:
            continue
        if _returns_a_response_object(route.endpoint):
            offenders.append(
                f"{method} {route.path} declares "
                f"{route.response_model.__name__} but returns a Response object"
            )
    assert not offenders, (
        "advertised-but-unenforced response models:\n  " + "\n  ".join(offenders)
        + "\nEither return a value on the success path, or record the route in "
          "DOCUMENTATION_ONLY_EXCEPTIONS with the reason."
    )


def test_recorded_exceptions_are_not_stale():
    """An exception that no longer applies is a false statement about the API."""
    for key in DOCUMENTATION_ONLY_EXCEPTIONS:
        route = next((r for r, m in _public_routes() if (r.path, m) == key), None)
        assert route is not None, f"exception recorded for a route that is gone: {key}"
        assert route.response_model is not None, (
            f"{key} is recorded as a documentation-only exception but declares no "
            "response model, so nothing is being advertised"
        )


@pytest.mark.parametrize("key", sorted(NON_MODEL_ROUTES))
def test_non_model_routes_still_declare_no_model(key):
    """These two are deliberately outside the response-model work. If one gains a
    model, that is a decision to make explicitly, not a side effect of a family
    conversion."""
    route = next((r for r, m in _public_routes() if (r.path, m) == key), None)
    assert route is not None, f"{key} is recorded as a non-model route but is gone"
    assert route.response_model is None, (
        f"{key} gained a response model. Reason it was excluded: "
        f"{NON_MODEL_ROUTES[key]}"
    )


def test_the_enforcement_classification_is_reported():
    """Not an assertion about the desired state -- a census, so the split is
    visible in the run and a regression in it is legible."""
    enforced, bypassing, advertised = [], [], []
    for route, method in _public_routes():
        returns_response = _returns_a_response_object(route.endpoint)
        if route.response_model is not None:
            advertised.append((method, route.path))
        if returns_response:
            bypassing.append((method, route.path))
        else:
            enforced.append((method, route.path))

    total = len(list(_public_routes()))
    assert total == len(PUBLIC_ROUTES), (
        f"matched {total} routes against {len(PUBLIC_ROUTES)} declared public ones"
    )
    # Today: three routes return values, the rest return Response objects, and
    # none declares a model. Pinned so a change in the split is deliberate.
    assert len(enforced) == 3, f"routes returning a value: {sorted(enforced)}"
    assert len(bypassing) == total - 3
    assert advertised == [], f"routes now advertising a model: {sorted(advertised)}"
