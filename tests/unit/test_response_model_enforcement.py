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

RETURN ANALYSIS. Three mistakes make this kind of check report nonsense, and all
three are handled:

  * a `return` inside a nested helper defined in the endpoint body is not the
    endpoint's return -- an earlier pass counted `_rows()` inside
    `get_key_addresses` and misread the route as returning a value;
  * a call to `_set_status()` or any other helper that builds a Response IS a
    Response return. Reading only the literal `JSONResponse(` calls misses them
    and overstates enforcement;
  * an ERROR-ENVELOPE return is not a success-path bypass. A route may return a
    value on success and `error_response(...)` on a failure, and it is fully
    enforced: the model applies to every success body, while the error carries
    the catalog envelope and is declared through `responses={...}` instead.
    `POST /v1/ai/request` is exactly this shape -- a provider failure returns
    502 LLM_UNAVAILABLE rather than a scan body. Counting that as a bypass would
    force the choice between an unenforced success path and raising an error the
    route deliberately returns, so the audit row it just wrote still lands.

The distinction is drawn by name, over the small closed set of builders whose
entire purpose is an error envelope. A helper added to that set is a claim that
it can never produce a success body.
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

# Builders that can only ever produce an error body: the canonical catalog
# envelope, and the OpenAI-compatible rejections on the proxy route. A return of
# one of these is a failure path, not a success path that skipped its model.
_ERROR_ENVELOPE_BUILDERS = {
    "error_response",    # errors/response.py -- the single canonical envelope
    "_error_response",   # proxy.py -- OpenAI-compatible envelope
    "_reject",           # proxy.py -- OpenAI-compatible refusal
    "_bad_request",      # admin/tenants.py
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
    ("/v1/settings/proxy", "DELETE"):
        "Answers 204 with an empty body. A response model describes a body, and "
        "there is none -- giving it one would advertise an empty schema for a "
        "response that carries no content.",
    ("/v1/audit/export", "GET"):
        "Returns CSV, not JSON. A response model describes a JSON body and would "
        "misdescribe this one; the media type is the contract here.",
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


def _is_error_construction(call: ast.Call) -> bool:
    """Whether a Response construction carries an explicit non-2xx status.

    `JSONResponse(status_code=404, content=...)` can only be a failure path, so a
    return of it is not a success body that skipped its model. Read from the
    literal keyword rather than inferred from the variable name, so renaming
    `not_found` to anything else changes nothing.
    """
    for kw in call.keywords:
        if kw.arg == "status_code" and isinstance(kw.value, ast.Constant):
            return isinstance(kw.value.value, int) and kw.value.value >= 400
    return False


def _returns_a_response_object(endpoint, *, count_error_envelopes: bool = True) -> bool:
    """Whether any of the endpoint's own returns yields a Response object.

    Resolves three forms: a direct construction, a call to a Response-returning
    helper, and a name bound to a Response earlier in the function (the
    `response = JSONResponse(...); ...; return response` shape used by the auth
    routes).

    With `count_error_envelopes=False`, a return of an error-envelope builder is
    ignored, and so is a Response constructed with an explicit non-2xx status --
    both answer the narrower question the bypass invariant asks: does a SUCCESS
    body leave this endpoint without passing through its model. The proxy
    interaction detail route is the second shape: it binds a 404 to a name,
    returns that name on three scoping branches, and returns its success body as
    a value.
    """
    error_builders = set() if count_error_envelopes else _ERROR_ENVELOPE_BUILDERS
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
        and not (not count_error_envelopes and _is_error_construction(node.value))
    }

    for node in _own_returns(fndef):
        value = node.value
        if isinstance(value, ast.Call):
            fn = value.func
            called = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            if called in error_builders:
                continue
            if not count_error_envelopes and _is_error_construction(value):
                continue
            if called in _RESPONSE_CLASSES or called in _HELPERS:
                return True
        elif isinstance(value, ast.Name) and value.id in response_names:
            return True
        elif isinstance(value, ast.Await):
            inner = value.value
            if isinstance(inner, ast.Call):
                fn = inner.func
                called = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
                if called in error_builders:
                    continue
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


def test_fastapi_rejects_a_body_the_model_cannot_accept():
    """The other half of the premise, and the one the per-family probes rest on.

    The test above pins FILTERING: an undeclared field is stripped. That alone
    does not show the model REJECTS anything, and a suite that only ever adds
    fields would never find out. These three are the mutations the family probes
    apply, checked once here against the installed framework so that a change in
    its behaviour fails in one obvious place rather than as a scatter of
    per-family tests that quietly stop meaning anything.

    Note what the second case establishes: responses are served with unset
    fields excluded, so an absent OPTIONAL field is normal. A required field
    going missing therefore has to be the loud case, or the two are
    indistinguishable on the wire.
    """
    class Nested(BaseModel):
        depth: int

    class Model(BaseModel):
        required_field: str
        number:         float
        nested:         Nested

    probe = FastAPI()
    good  = {"required_field": "a", "number": 1.0, "nested": {"depth": 1}}

    @probe.get("/ok", response_model=Model, response_model_exclude_unset=True)
    def _ok():
        return dict(good)

    @probe.get("/missing", response_model=Model, response_model_exclude_unset=True)
    def _missing():
        return {k: v for k, v in good.items() if k != "required_field"}

    @probe.get("/wrong-type", response_model=Model, response_model_exclude_unset=True)
    def _wrong_type():
        return {**good, "number": "not-a-number"}

    @probe.get("/bad-nested", response_model=Model, response_model_exclude_unset=True)
    def _bad_nested():
        return {**good, "nested": "not-an-object"}

    client = TestClient(probe, raise_server_exceptions=False)

    assert client.get("/ok").status_code == 200, (
        "the control body was refused, so the probe proves nothing about the rest"
    )
    for path, mutation in (("/missing",    "a missing required field"),
                           ("/wrong-type", "an uncoercible type"),
                           ("/bad-nested", "a nested model replaced by a scalar")):
        assert client.get(path).status_code == 500, (
            f"the framework SERVED a body carrying {mutation}. Response-model "
            "validation is not active, and every rejection test in this suite "
            "is passing for the wrong reason."
        )


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
        if _returns_a_response_object(route.endpoint, count_error_envelopes=False):
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


# Routes whose success body reaches the response model. The list grows one API
# family at a time; each entry is a route whose success return was converted from
# a constructed Response to a value, or that already returned one.
MODELLED_ROUTES: set[tuple[str, str]] = {
    ("/v1/ai/request", "POST"),
    ("/v1/ai/scan-batch", "POST"),
    ("/v1/ai/requests/{trace_id}", "GET"),
    ("/v1/agent-runs/{run_id}", "GET"),
    ("/v1/audit/logs", "GET"),
    ("/v1/audit/stats", "GET"),
    ("/health", "GET"),
    ("/health/live", "GET"),
    ("/health/ready", "GET"),
    ("/health/config", "GET"),
    ("/v1/capabilities", "GET"),
    ("/v1/proxy/interactions", "GET"),
    ("/v1/proxy/interactions/{trace_id}", "GET"),
    ("/v1/keys", "GET"),
    ("/v1/keys", "POST"),
    ("/v1/settings/thresholds", "GET"), ("/v1/settings/thresholds", "PUT"),
    ("/v1/settings/layers", "GET"), ("/v1/settings/layers", "PUT"),
    ("/v1/settings/llm", "GET"), ("/v1/settings/llm", "PUT"),
    ("/v1/settings/rate_limit", "GET"), ("/v1/settings/rate_limit", "PUT"),
    ("/v1/settings/proxy", "GET"), ("/v1/settings/proxy", "PUT"),
    # OpenAI-compatible, and modelled on its own protocol shape rather than the
    # WrapSec one: its success body has a response model, while its OpenAI error
    # bodies stay constructed Responses, which is what they must be.
    ("/v1/chat/completions", "POST"),
}


def test_every_modelled_route_declares_a_model_and_enforces_it():
    """The two halves have to hold together: declaring a model the runtime skips
    advertises a promise nothing keeps, and converting a success return without
    declaring a model enforces nothing."""
    for key in sorted(MODELLED_ROUTES):
        route = next((r for r, m in _public_routes() if (r.path, m) == key), None)
        assert route is not None, f"{key} is recorded as modelled but no longer exists"
        assert route.response_model is not None, (
            f"{key} is recorded as modelled but declares no response_model"
        )
        assert not _returns_a_response_object(route.endpoint, count_error_envelopes=False), (
            f"{key} declares {route.response_model.__name__} but returns a Response "
            "object on a success path, so the model is never applied"
        )


def test_the_enforcement_classification_is_reported():
    """Not an assertion about the desired state -- a census, so the split is
    visible in the run and a regression in it is legible.

    `enforced` here means "no success body leaves without passing the model",
    which is why the error-envelope returns are not counted: a route that answers
    a provider failure with the catalog envelope still enforces its success
    contract.
    """
    enforced, bypassing, advertised = [], [], []
    for route, method in _public_routes():
        returns_response = _returns_a_response_object(
            route.endpoint, count_error_envelopes=False,
        )
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
    # Today: the health and capabilities family, the converted scan family, the
    # agent-run timeline and the two audit read-back routes return values; every
    # other public route still returns a constructed Response and declares
    # nothing. Pinned so a change in the split is deliberate. `/health/ready`
    # joined the enforced set by moving its 503 onto the injected Response,
    # which is what lets its body pass through the model.
    assert len(enforced) == 26, f"routes returning a value: {sorted(enforced)}"
    assert len(bypassing) == total - 26
    assert sorted(advertised) == sorted(
        (method, path) for path, method in MODELLED_ROUTES
    ), f"routes advertising a model: {sorted(advertised)}"
