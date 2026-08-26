# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Structural guards on the published OpenAPI schema.

`docs/openapi.json` is the advertised contract. Three things can go wrong with it
quietly, and each is checked here:

  * a plugin route reaches the published schema, advertising an endpoint the OSS
    build does not serve;
  * the generator stops being deterministic, so unrelated commits carry schema
    noise and a real change hides in it;
  * the committed file drifts from the application and nobody notices, because
    nothing reads the file back.

The public boundary is held in BOTH directions: the published schema is exactly
the frozen 28-route integrator surface. A route that stops being published fails
one test; a route that starts being published fails the other. Operator,
dashboard and first-run routes are excluded through `include_in_schema` in
`api/v1/router.py` and in the four partly-public routers -- documentation scope
only, no change to routing, authorization or behaviour.

The surface itself is defined once, in `test_response_model_enforcement.py`, and
imported here. Two copies of a 28-entry list would drift, and the two tests would
then disagree about what "public" means while both passing.

The word PUBLIC also means something different in `test_route_isolation_guard.py`:
there it means "reachable without authentication". A route can be authenticated
and still belong to the published API surface. Do not merge the three lists.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA    = _REPO_ROOT / "docs" / "openapi.json"
_GENERATOR = _REPO_ROOT / "scripts" / "gen_openapi.py"


def _committed() -> dict:
    return json.loads(_SCHEMA.read_text(encoding="utf-8"))


def test_the_committed_schema_exists_and_parses():
    spec = _committed()
    assert spec["openapi"].startswith("3.")
    assert spec["info"]["title"] == "WrapSec"
    assert spec["paths"], "a schema with no paths would pass every other check here"


def test_the_committed_schema_matches_the_application():
    """`--check` is the drift detector. If this fails, the schema was not
    regenerated alongside a route or model change: run scripts/gen_openapi.py and
    read the diff before committing it."""
    result = subprocess.run(
        [sys.executable, str(_GENERATOR), "--check"],
        cwd=_REPO_ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, (
        f"docs/openapi.json is stale:\n{result.stdout}\n{result.stderr}"
    )


def test_check_reports_drift_rather_than_passing_quietly():
    """The test above only proves `--check` passes when the file is current, which
    a `--check` that always returned 0 would also do. This proves it fails on a
    stale file, so the drift detector detects drift.

    Run against a temporary tree rather than the real `docs/openapi.json`: the
    check must never be proven by making the committed baseline wrong.
    """
    import tempfile

    sys.path.insert(0, str(_REPO_ROOT))
    import scripts.gen_openapi as gen

    rendered = gen._render()

    with tempfile.TemporaryDirectory() as tmp:
        root   = Path(tmp)
        target = root / "docs" / "openapi.json"
        target.parent.mkdir(parents=True)

        original_root, original_target = gen._REPO_ROOT, gen._TARGET
        original_argv = sys.argv
        try:
            gen._REPO_ROOT, gen._TARGET = root, target
            sys.argv = ["gen_openapi.py", "--check"]

            target.write_text(rendered.replace('"openapi"', '"openapi_stale"', 1), encoding="utf-8")
            assert gen.main() == 1, "--check accepted a schema that differs from the app"

            target.write_text(rendered, encoding="utf-8")
            assert gen.main() == 0, "--check rejected a schema identical to the app"
        finally:
            gen._REPO_ROOT, gen._TARGET = original_root, original_target
            sys.argv = original_argv


def test_generation_is_deterministic():
    """Two renders of the same application must be byte-identical, so a schema
    diff always means a contract change rather than dict ordering.

    Rendered in-process and compared directly. Capturing the generator's stdout
    would compare the process output, which carries a timestamped startup log
    line and is nondeterministic for reasons that have nothing to do with the
    schema.
    """
    sys.path.insert(0, str(_REPO_ROOT))
    import scripts.gen_openapi as gen

    assert gen._render() == gen._render()


def test_no_plugin_route_is_in_the_published_schema():
    """The published schema is the OSS contract. A plugin registers routes through
    the `wrapsec.plugins` entry-point group, so an editable install of one in the
    build environment is enough to leak a paid endpoint into it.

    Checked against the core route inventory rather than a name pattern: a plugin
    route need not be called anything in particular.
    """
    from fastapi.routing import APIRoute

    from api.main import app

    core_paths = {
        r.path for r in app.routes
        if isinstance(r, APIRoute) and r.include_in_schema
        and r.endpoint.__module__.startswith(("api.", "fastapi"))
    }
    published = set(_committed()["paths"])

    foreign = published - core_paths
    assert not foreign, (
        f"paths in the published schema that no core `api.*` route serves: "
        f"{sorted(foreign)}"
    )


def test_the_generator_refuses_when_a_plugin_is_registered(monkeypatch):
    """The refusal is the actual control -- the check above only sees what the
    current environment produced. Proven by registering a capability rather than
    by trusting the guard's presence."""
    sys.path.insert(0, str(_REPO_ROOT))
    import scripts.gen_openapi as gen
    from services import capabilities

    monkeypatch.setattr(capabilities, "get_capabilities", lambda: ["paid_feature"])

    with pytest.raises(SystemExit) as caught:
        gen._render()
    assert "core build" in str(caught.value)


# ── the public boundary ──────────────────────────────────────────────────────

def test_every_public_route_is_published():
    """The frozen public surface must be advertised in full.

    A route dropping out of the schema is invisible otherwise: `--check` compares
    the file against the application, so a route that stops being published
    updates the baseline and passes. This compares the baseline against the
    surface an SDK and the MCP adapter are documented to call.
    """
    from tests.unit.test_response_model_enforcement import PUBLIC_ROUTES

    assert len(PUBLIC_ROUTES) == 28, (
        f"the public surface is now {len(PUBLIC_ROUTES)} routes. Widening or "
        "narrowing it is a contract decision -- make it deliberately, then update "
        "this count."
    )

    paths   = _committed()["paths"]
    missing = [
        f"{method} {path}" for path, method in PUBLIC_ROUTES
        if method.lower() not in paths.get(path, {})
    ]
    assert not missing, (
        f"public routes absent from the published schema: {sorted(missing)}"
    )


def test_nothing_outside_the_public_surface_is_published():
    """The other direction, and the one that keeps internal surface internal.

    Operator, dashboard and first-run routes are served but not advertised. A new
    route is published by default, so without this a dashboard-only endpoint joins
    the integrator contract the moment someone adds it -- and the baseline file
    would be regenerated to match, making the drift check agree with it.
    """
    from tests.unit.test_response_model_enforcement import PUBLIC_ROUTES

    published = {
        (path, method.upper())
        for path, operations in _committed()["paths"].items()
        for method in operations
        if method in ("get", "post", "put", "patch", "delete")
    }
    extra = published - PUBLIC_ROUTES
    assert not extra, (
        f"routes published beyond the integrator surface: {sorted(extra)}. "
        "Either they belong to the public API -- a contract decision, recorded by "
        "adding them to PUBLIC_ROUTES -- or they need include_in_schema=False."
    )


def test_the_read_back_route_declares_a_422_it_can_reach():
    """`GET /v1/ai/requests/{trace_id}` documents a 422 that is now real.

    THIS TEST USED TO ASSERT THE OPPOSITE, and the change is the point. FastAPI
    publishes a 422 for any route with a parameter and offers no way to remove
    that entry, only to override it. While the path parameter was an
    unconstrained string nothing could fail validation, so the entry described a
    status the route could not produce -- recorded then as the one place in this
    work where an unreachable status is declared, because the choice was between
    two unreachable entries and the correct shape won.

    It is reachable now. The parameter carries a constraint forbidding a NUL,
    which is the byte no stored identifier can contain, so a path segment
    containing one is refused by the validation handler before the lookup runs.
    That closed a defect where the value reached asyncpg and the caller got a
    500.

    What is asserted is the PREMISE behind the declaration, read the way FastAPI
    reads it: one path parameter, constrained, and no body. If the constraint is
    removed the 422 stops being reachable and its description becomes a promise
    nothing keeps -- which is what this test then fails for.
    """
    from fastapi.dependencies.utils import get_flat_params
    from fastapi.routing import APIRoute

    from api.main import app

    route = next(
        r for r in app.routes
        if isinstance(r, APIRoute) and r.path == "/v1/ai/requests/{trace_id}"
    )
    params = get_flat_params(route.dependant)

    assert [p.name for p in params] == ["trace_id"], (
        f"the route now validates {[p.name for p in params]}; every one of those "
        "must be covered by the 422 description"
    )
    # The constraint rides on the ANNOTATION (`Annotated[str, StringConstraints]`),
    # which is where FastAPI reads it from; `field_info.metadata` stays empty for
    # a path parameter declared this way.
    constraints = getattr(params[0].field_info.annotation, "__metadata__", ())
    assert constraints, (
        "the path parameter lost its constraint, so a NUL reaches the database "
        "again and the declared 422 is unreachable"
    )
    assert any(getattr(c, "pattern", None) for c in constraints), (
        f"expected a pattern constraint on trace_id, found {constraints}"
    )
    assert route.body_field is None, "the route gained a body, which can fail validation"


# ── the two deliberate special cases ─────────────────────────────────────────

def test_audit_export_is_advertised_as_csv():
    """The CSV route advertises CSV. This replaces a pinned misrepresentation.

    It used to publish a 200 of `application/json` with an empty schema, because
    a FastAPI route derives its advertised media type from its response class and
    the default one is JSON. The handler streams `text/csv`, so the published
    contract told a generator to expect the wrong thing. Declaring the response
    class fixed the derivation; the empty JSON entry is gone rather than sitting
    alongside the CSV one.

    The route is still a deliberate non-model exception -- see NON_MODEL_ROUTES.
    This asserts the media type, which is the contract for a file download; the
    absence of a response model is asserted separately, next to that record.
    """
    spec = _committed()
    ok = spec["paths"]["/v1/audit/export"]["get"]["responses"]["200"]
    content = ok.get("content") or {}

    assert list(content) == ["text/csv"], (
        f"audit/export advertises {list(content)}; it streams text/csv, and an "
        "application/json entry here tells a generator to parse a CSV body as JSON"
    )
    assert content["text/csv"]["schema"] == {"type": "string", "format": "binary"}, (
        "the CSV body is advertised as something other than a binary string"
    )


def test_no_published_operation_advertises_the_generated_validation_schema():
    """`HTTPValidationError` describes a body this application never emits.

    FastAPI generates it for any parameterized route, but a request-validation
    failure is answered by the global handler with the catalog `ErrorEnvelope` --
    different field names, different nesting. A caller coding against the
    generated schema would parse `detail[].loc` and find nothing.

    Asserted over the whole published surface rather than per route, so a NEW
    route cannot quietly reintroduce it: adding one without declaring its 422 is
    what fails here. The two component schemas are checked as well, because they
    are dropped only while nothing references them, and their reappearance is the
    same defect one level down.
    """
    spec = _committed()

    offenders = [
        f"{method.upper()} {path}"
        for path, ops in spec["paths"].items()
        for method, op in ops.items()
        if "HTTPValidationError" in json.dumps(op)
    ]
    assert offenders == [], (
        f"these operations advertise HTTPValidationError: {offenders}. Declare the "
        "route's 422 as ErrorEnvelope -- that is the body the runtime returns."
    )

    schemas = spec["components"]["schemas"]
    assert "HTTPValidationError" not in schemas and "ValidationError" not in schemas, (
        "the generated validation schemas are back in components, so something "
        "references them again"
    )


def test_chat_completions_advertises_its_own_protocol_shape():
    """The OpenAI-compatible route, modelled on its OWN protocol.

    This pinned the opposite until the chat family was converted: the route
    advertised no response schema at all, on the reasoning that its body is
    provider-shaped. It now advertises a model built from the measured body --
    which is not the OpenAI specification's, since this implementation sends no
    `created`, exactly one choice, and an optional `wrapsec` block.

    What must NOT happen is the WrapSec envelope leaking onto its OpenAI-shaped
    errors. FOUR statuses are the measured exceptions, all answered before or
    outside the OpenAI-compatible path: 401 and 409 come from middleware (auth
    and idempotency), 422 from the global validation handler, and 403 refuses a
    dashboard session. Every error the route itself builds stays OpenAI-shaped.

    429 belongs to neither group -- it has one producer on each side -- and is
    asserted separately.

    401 and 409 were reachable and canonical well before they were declared --
    neither is mentioned anywhere in this route's source, which is why they were
    missed. Both are measured over HTTP in the integration suite.
    """
    op = _committed()["paths"]["/v1/chat/completions"]["post"]
    ref = lambda code: (
        (op["responses"][code].get("content") or {})
        .get("application/json", {}).get("schema", {}).get("$ref", "").split("/")[-1]
    )

    assert ref("200") == "ChatCompletionResponse"

    # 429 is excluded here and asserted on its own below: it is the one status
    # with two producers, so it is the one status that is NOT a single $ref.
    for code in ("400", "413", "500", "502", "504"):
        assert ref(code) == "OpenAIErrorResponse", (
            f"{code} on the OpenAI-compatible route advertises {ref(code)!r}; its "
            "callers parse error.message / error.type / error.code"
        )

    for code in ("401", "403", "409", "422"):
        assert ref(code) == "ErrorEnvelope", (
            f"{code} is answered by WrapSec rather than by the OpenAI-compatible "
            f"path, so it must advertise the catalog envelope, not {ref(code)!r}"
        )


def test_the_proxy_interaction_detail_404_advertises_the_catalog_envelope():
    """The 404 that was converted from a reduced body to the catalog envelope.

    Phase A deliberately left this undeclared: the route returned
    `{"error": {code, message}}`, and advertising `ErrorEnvelope` would have
    promised fields the runtime did not send. The runtime now sends the full
    envelope, so the declaration follows the behaviour rather than leading it --
    the integration suite measures the body, this asserts the published contract
    agrees.

    The LIST route is asserted to have no 404 at all: it answers an empty result
    with `{"total": 0, "items": []}`, and a documented status nothing produces is
    a promise nothing keeps.
    """
    paths = _committed()["paths"]

    detail = paths["/v1/proxy/interactions/{trace_id}"]["get"]["responses"]
    assert "404" in detail, "the detail route's 404 is undeclared again"
    ref = (detail["404"]["content"]["application/json"]["schema"]["$ref"]).split("/")[-1]
    assert ref == "ErrorEnvelope", f"the 404 advertises {ref!r}"

    assert "404" not in paths["/v1/proxy/interactions"]["get"]["responses"], (
        "the list route advertises a 404 it never produces"
    )


def test_the_proxy_settings_errors_are_declared_where_they_occur():
    """The proxy-settings family after its error envelopes were canonicalized.

    Two different defects were corrected here, and they had opposite polarity:

      * the read and the delete answer 404 and declared nothing;
      * the upsert DECLARED `422: ErrorEnvelope` while one of its two branches
        returned a reduced body -- a published statement that was false.

    So the upsert's declaration is unchanged by that work and is asserted anyway:
    the fix was to make the runtime match it, and a later edit that "corrects" the
    schema instead would pass every other test in this file.

    The upsert is also asserted to have NO 404. It upserts -- a missing row is
    what it creates, not an error -- so declaring one would document a status it
    cannot produce.
    """
    proxy = _committed()["paths"]["/v1/settings/proxy"]
    ref = lambda method, code: (
        (proxy[method]["responses"].get(code, {}).get("content") or {})
        .get("application/json", {}).get("schema", {}).get("$ref", "").split("/")[-1]
    )

    for method in ("get", "delete"):
        assert "404" in proxy[method]["responses"], (
            f"{method.upper()} /v1/settings/proxy answers 404 but declares none"
        )
        assert ref(method, "404") == "ErrorEnvelope", (
            f"{method.upper()} 404 advertises {ref(method, '404')!r}"
        )

    assert ref("put", "422") == "ErrorEnvelope", (
        "the upsert's 422 no longer advertises the catalog envelope; both of its "
        "branches return one"
    )
    assert "404" not in proxy["put"]["responses"], (
        "the upsert advertises a 404 it never produces"
    )


# Public error responses that are produced by shared machinery -- middleware, a
# rate-limit dependency, the global validation handler -- rather than by the
# route's own body. They were reachable and canonical long before they were
# declared, which is exactly why they went unnoticed: nothing about the route
# source mentions them.
#
# Each entry is (path, method, status, code) and is backed by a runtime test
# that triggers the condition over HTTP and asserts the same code. This checks
# the published half of that pair.
_SHARED_ERROR_DECLARATIONS = [
    ("/v1/audit/export",            "get",  "400", "INVALID_REQUEST"),
    ("/v1/audit/export",            "get",  "401", "UNAUTHORIZED"),
    ("/v1/audit/export",            "get",  "429", "RATE_LIMIT_EXCEEDED"),
    ("/v1/ai/requests/{trace_id}",  "get",  "429", "RATE_LIMIT_EXCEEDED"),
    ("/v1/ai/request",              "post", "409", "IDEMPOTENCY_CONFLICT"),
    ("/v1/chat/completions",        "post", "401", "UNAUTHORIZED"),
    ("/v1/chat/completions",        "post", "409", "IDEMPOTENCY_CONFLICT"),
]


@pytest.mark.parametrize(
    ("path", "method", "status", "code"),
    _SHARED_ERROR_DECLARATIONS,
    ids=[f"{m.upper()} {p} {s}" for p, m, s, _ in _SHARED_ERROR_DECLARATIONS],
)
def test_a_reachable_shared_error_is_declared_as_the_catalog_envelope(path, method, status, code):
    """Declared, and declared as the envelope the runtime actually returns.

    Asserting only that the status key exists would pass for an entry with no
    schema, or with the wrong one -- which is the defect this whole phase exists
    to remove, not a weaker version of it. The `$ref` is what a generator reads.

    `code` is carried here for the runtime counterpart to match on; it is not
    published in the schema (the envelope declares `code` as a string, not an
    enum of every catalog member), so it is not asserted against the spec.
    """
    responses = _committed()["paths"][path][method]["responses"]

    assert status in responses, (
        f"{method.upper()} {path} answers {status} {code} at runtime but declares "
        "no such response"
    )
    ref = (
        (responses[status].get("content") or {})
        .get("application/json", {}).get("schema", {}).get("$ref", "").split("/")[-1]
    )
    assert ref == "ErrorEnvelope", (
        f"{method.upper()} {path} {status} advertises {ref!r}; the runtime returns "
        f"the catalog envelope with code {code}"
    )


def test_the_csv_export_gained_error_declarations_without_gaining_a_json_success():
    """The export's 200 must stay CSV-only while its error set grows.

    Its errors are `application/json` and its success is not, so adding the one
    is the most plausible way to reintroduce the other -- which was the original
    defect on this route.
    """
    export = _committed()["paths"]["/v1/audit/export"]["get"]["responses"]

    assert list(export["200"]["content"]) == ["text/csv"], (
        f"the export success media types are {list(export['200']['content'])}"
    )
    for status in ("400", "401", "422", "429"):
        assert list(export[status]["content"]) == ["application/json"], (
            f"the export {status} is not application/json"
        )


def test_the_chat_429_advertises_both_of_its_producers():
    """The one status on this route with two legitimate producers.

    The gateway's own limiter refuses with the catalog envelope; an upstream
    provider refusal is mapped by the route and stays OpenAI-shaped. Both are
    real, so advertising either alone was a false statement about half the
    traffic that reaches this status.

    WHY `anyOf` AND NOT `oneOf`. These are alternative producers, not a
    discriminated union -- nothing requires a body to match exactly one branch,
    and there is no discriminator field to key on. `anyOf` is also the keyword
    this schema already uses wherever a union appears, so it asks nothing new of
    a consumer that already reads it.

    NOT VERIFIED: how an EXTERNAL code generator handles this. No generator
    consumes `docs/openapi.json` in this repository -- both SDKs are hand
    written -- so the claim is only that the schema is accurate, not that every
    downstream toolchain renders it well. That limitation is deliberate and
    should stay recorded here rather than being quietly assumed away.

    Fails if either branch disappears, which is the point: dropping one is how
    this silently reverts to describing half the behaviour.
    """
    schema = (
        _committed()["paths"]["/v1/chat/completions"]["post"]
        ["responses"]["429"]["content"]["application/json"]["schema"]
    )

    assert "oneOf" not in schema, "the 429 union became exclusive; see the docstring"
    assert "anyOf" in schema, (
        f"the 429 is advertised as a single schema again: {schema}"
    )

    branches = {b.get("$ref", "").split("/")[-1] for b in schema["anyOf"]}
    assert branches == {"OpenAIErrorResponse", "ErrorEnvelope"}, (
        f"the 429 advertises {sorted(branches)}; both producers must be present "
        "-- the gateway limiter (catalog envelope) and the upstream provider "
        "refusal (OpenAI-shaped)"
    )


def test_the_settings_family_describes_every_published_field():
    """Phase C, one family at a time: the settings schemas describe what they serve.

    A description is documentation, not a runtime control -- nothing enforces it,
    and nothing about a response changes when one is added. That is exactly why it
    needs a test: a field added later without one costs nothing at runtime, fails
    no other check, and quietly leaves a hole in the published contract.

    Read from the GENERATED artifact rather than the models, because the artifact
    is what an integrator and a code generator consume. A description that exists
    on the model but does not reach `docs/openapi.json` has not been delivered.

    Scoped to the settings family on purpose. The other families are converted in
    their own passes; widening this list before their pass would fail for work
    that has not been done yet, which is a broken test rather than a finding.
    """
    schemas = _committed()["components"]["schemas"]

    family = [
        "ThresholdsResponse", "ThresholdsUpdatedResponse",
        "DetectionLayersResponse", "DetectionLayersUpdatedResponse",
        "RateLimitResponse", "RateLimitUpdatedResponse",
        "LLMSettingsResponse", "LLMSettingsUpdatedResponse",
        "ProxyProviderConfigResponse",
    ]

    undescribed = [
        f"{name}.{prop}"
        for name in family
        for prop, spec in schemas[name]["properties"].items()
        if not (spec.get("description") or "").strip()
    ]

    assert not undescribed, (
        f"published settings fields with no description: {undescribed}. "
        "Add one that says something the field name does not, or state here why "
        "the field is self-explanatory."
    )
