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
import re
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

    429 and 500 belong to neither group -- each has one producer on each side --
    and both are asserted separately. The 500 joined them once the degraded-policy
    refusal was measured on this route: policy is resolved before the
    OpenAI-compatible path is reachable, so that refusal is raised as a
    WrapSecError and answered by the global handler in the catalog envelope,
    while an output-guard or post-provider failure stays OpenAI-shaped.

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

    # 429 and 500 are excluded here and asserted on their own below: they are
    # the two statuses with a producer on each side, so they are the two that
    # are NOT a single $ref.
    for code in ("400", "413", "502", "504"):
        assert ref(code) == "OpenAIErrorResponse", (
            f"{code} on the OpenAI-compatible route advertises {ref(code)!r}; its "
            "callers parse error.message / error.type / error.code"
        )

    for code in ("401", "403", "409", "422"):
        assert ref(code) == "ErrorEnvelope", (
            f"{code} is answered by WrapSec rather than by the OpenAI-compatible "
            f"path, so it must advertise the catalog envelope, not {ref(code)!r}"
        )

    # The 500's two producers, in the same form the 429 uses. Asserted here as
    # well as in the integration suite because the suite measures the body and
    # this measures the promise; the defect was the two disagreeing.
    schema_500 = (
        op["responses"]["500"]["content"]["application/json"]["schema"]
    )
    assert "oneOf" not in schema_500, "the 500 union became exclusive"
    branches_500 = {b.get("$ref", "").split("/")[-1]
                    for b in schema_500.get("anyOf", [])}
    assert branches_500 == {"OpenAIErrorResponse", "ErrorEnvelope"}, (
        f"the 500 advertises {sorted(branches_500) or schema_500!r}; both "
        "producers must be present -- an unresolved policy (catalog envelope) "
        "and an output-guard or post-provider failure (OpenAI-shaped)"
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
    # Both 403s below were reachable and undeclared until a recording of what the
    # suite actually receives over HTTP found them. Neither is raised by the
    # route's own body, which is why reading the handler never showed them, and
    # neither is specific to the operation -- the source restriction applies to
    # every api-key endpoint and the password gate to every jwt one. They are
    # declared HERE and not on their siblings because a declaration claims the
    # status is reachable AND tested at that operation, and these two are the
    # ones with that evidence.
    ("/v1/ai/scan-batch",           "post", "403", "IP_NOT_ALLOWED"),
    ("/v1/audit/logs",              "get",  "403", "PASSWORD_CHANGE_REQUIRED"),
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


# ── Phase C / F-030 Option B: published allowed values ───────────────────────

# The ai/scan family, and the vocabulary each field publishes. Listed here rather
# than derived from the schema, so a field that silently LOSES its enum fails.
_AI_FAMILY_ENUMS = {
    ("ScanResponse", "decision"):                    "DECISIONS",
    ("ScanResponse", "primary_reason"):              "PRIMARY_REASONS",
    ("ScanResponse", "confidence_band"):             "CONFIDENCE_BANDS",
    ("Assessment", "decision"):                      "DECISIONS",
    ("Assessment", "primary_reason"):                "PRIMARY_REASONS",
    ("Assessment", "confidence_band"):               "CONFIDENCE_BANDS",
    ("AssessmentLayer", "decision"):                 "DECISIONS",
    ("ScanProcessing", "detection_mode"):            "DETECTION_MODES",
    ("ScanProcessing", "execution_mode"):            "EXECUTION_MODES",
    ("BatchItemResult", "decision"):                 "DECISIONS",
    ("RequestRecordResponse", "decision"):           "DECISIONS",
    ("RequestRecordResponse", "primary_reason"):     "PRIMARY_REASONS",
    ("RequestRecordResponse", "confidence_band"):    "CONFIDENCE_BANDS",
    ("RequestRecordResponse", "severity"):           "SEVERITIES",
    ("RequestRecordResponse", "execution_mode"):     "EXECUTION_MODES",
    ("RequestRecordResponse", "input_source"):       "INPUT_SOURCES",
    ("RecordProcessing", "detection_mode"):          "DETECTION_MODES",
    ("RecordProcessing", "execution_mode"):          "EXECUTION_MODES",
    ("RecordProxyDetail", "provider"):               "PROXY_PROVIDERS",
    ("RecordProxyDetail", "execution_status"):       "EXECUTION_STATUSES",
    ("RecordProxyDetail", "input_primary_reason"):   "PRIMARY_REASONS",
    ("RecordProxyDetail", "output_decision"):        "DECISIONS",
    ("RecordProxyDetail", "output_primary_reason"):  "PRIMARY_REASONS",
}

# The audit family. Every one of these is read back from a `VARCHAR` column, so
# the same caveat applies as for the ai/scan read-back: this asserts what the
# SCHEMA publishes, never what a stored row contains.
_AUDIT_FAMILY_ENUMS = {
    ("AuditItem", "decision"):         "DECISIONS",
    ("AuditItem", "output_decision"):  "DECISIONS",
    ("AuditItem", "provider"):         "PROXY_PROVIDERS",
    ("AuditItem", "primary_reason"):   "PRIMARY_REASONS",
    ("AuditItem", "confidence_band"):  "CONFIDENCE_BANDS",
    ("AuditItem", "detection_mode"):   "DETECTION_MODES",
    ("AuditItem", "execution_mode"):   "EXECUTION_MODES",
    ("AuditItem", "severity"):         "SEVERITIES",
    ("AuditItem", "input_source"):     "INPUT_SOURCES",
    ("AuditItem", "policy_source"):    "POLICY_SOURCES",
    ("TopThreat", "category"):         "THREAT_CATEGORIES",
}


# The proxy-interactions family. The seven fields are declared once on
# `ProxyInteraction` and inherited by `ProxyInteractionDetail`, so both published
# schemas are checked -- inheritance is what carries the metadata, and a later
# refactor that flattened the models could drop it from the detail schema alone.
_PROXY_INTERACTION_FAMILY_ENUMS = {
    (model, prop): vocab
    for model in ("ProxyInteraction", "ProxyInteractionDetail")
    for prop, vocab in (
        ("input_decision",        "DECISIONS"),
        ("input_primary_reason",  "PRIMARY_REASONS"),
        ("input_attack_type",     "THREAT_CATEGORIES"),
        ("provider",              "PROXY_PROVIDERS"),
        ("execution_status",      "EXECUTION_STATUSES"),
        ("output_decision",       "DECISIONS"),
        ("output_primary_reason", "PRIMARY_REASONS"),
    )
}


# The chat family. NARROWER than the vocabularies the other families publish, and
# deliberately: a 200 chat body cannot carry a blocked decision or a non-success
# status, because the route returns before building it.
_CHAT_FAMILY_ENUMS = {
    ("ChatCompletionResponse", "object"):        "CHAT_OBJECT",
    ("ChatMessage", "role"):                     "CHAT_RESPONSE_ROLES",
    ("ChatCompletionMeta", "decision"):          "CHAT_META_DECISIONS",
    ("ChatCompletionMeta", "output_decision"):   "CHAT_META_DECISIONS",
    ("ChatCompletionMeta", "execution_status"):  "CHAT_META_STATUSES",
    ("ChatCompletionMeta", "input_primary_reason"): "PRIMARY_REASONS",
    ("ChatCompletionMeta", "provider"):          "PROXY_PROVIDERS",
}


# The keys family. One vocabulary, on both published projections. Both fields are
# non-nullable, so this is also the family that exercises `_allowed`'s top-level
# branch -- the nullable branch is covered everywhere else.
_KEYS_FAMILY_ENUMS = {
    ("ApiKeyCreated", "key_type"):  "KEY_TYPES",
    ("ApiKeyListItem", "key_type"): "KEY_TYPES",
}


# The health and capabilities family. Five distinct vocabularies, deliberately not
# merged: the probes report on different scales, and `Config*.source` is one
# vocabulary shared by four models rather than four similar-looking ones.
_HEALTH_FAMILY_ENUMS = {
    ("HealthResponse", "status"):               "HEALTH_STATUS",
    ("LivenessResponse", "status"):             "LIVENESS_STATUS",
    ("ReadinessResponse", "status"):            "READINESS_STATUS",
    ("HealthChecks", "database"):               "INFRA_CHECK_STATUSES",
    ("HealthChecks", "redis"):                  "INFRA_CHECK_STATUSES",
    ("HealthChecks", "tfidf_detector"):         "DETECTOR_CHECK_STATUSES",
    ("HealthChecks", "transformer_detector"):   "DETECTOR_CHECK_STATUSES",
    ("ConfigThresholds", "source"):             "CONFIG_SOURCES",
    ("ConfigDetectionLayers", "source"):        "CONFIG_SOURCES",
    ("ConfigLLM", "source"):                    "CONFIG_SOURCES",
    ("ConfigRateLimit", "source"):              "CONFIG_SOURCES",
    ("CapabilitiesResponse", "edition"):        "EDITIONS",
}

# The four models whose `source` is produced by one ternary. Listed separately
# because the risk is publishing it on ONE of them and calling the family done.
_CONFIG_SOURCE_MODELS = ("ConfigThresholds", "ConfigDetectionLayers",
                         "ConfigLLM", "ConfigRateLimit")


# Deliberately NOT enumerated, and why. Each is a field whose values this API does
# not control, so publishing a list would be a claim it cannot keep.
_NEVER_ENUMERATED = {
    ("LLMSettingsResponse", "provider"):        "published straight from an unvalidated env var",
    ("LLMSettingsUpdatedResponse", "provider"): "published straight from an unvalidated env var",
    ("ConfigLLM", "provider"):                  "published straight from an unvalidated env var",
    ("ChatChoice", "finish_reason"):            "whatever the upstream provider returned",
    ("AuditItem", "source"):                    "echoes metadata.source from the caller's own request",
    ("AuditItem", "threats"):                   "an array -- the enum belongs on its items, not the field",
    ("ProxyInteraction", "behavior_flag"):      "F-031: no writer ever sets it, so it is always null",
    ("ProxyInteraction", "output_flags"):       "F-031: no writer ever sets it, so it is always null",
    ("ProxyInteraction", "input_threats"):      "an array -- the enum belongs on its items, not the field",
    ("ProxyInteraction", "output_threats"):     "an array -- the enum belongs on its items, not the field",
    ("ProxyInteraction", "model"):              "the provider's own model name, free text",
    ("ProxyInteractionDetail", "behavior_flag"): "F-031: no writer ever sets it, so it is always null",
    ("ProxyInteractionDetail", "output_flags"):  "F-031: no writer ever sets it, so it is always null",
    ("ChatCompletionResponse", "model"):        "the provider's own model name, free text",
    ("ChatCompletionResponse", "usage"):        "the provider's token counts, passed through untouched",
    ("ChatCompletionMeta", "model"):            "the provider's own model name, free text",
    ("ApiKeyCreated", "api_key"):               "the credential itself; never a vocabulary",
    ("ApiKeyCreated", "name"):                  "caller-chosen label, free text",
    ("ApiKeyListItem", "name"):                 "caller-chosen label, free text",
    ("CapabilitiesResponse", "capabilities"):   "plugin-supplied names, extensible -- and an array",
    ("HealthResponse", "version"):              "the running build string",
    ("HealthConfigResponse", "version"):        "the running build string",
    ("AgentRunResponse", "run_id"):             "echoed back exactly as the caller sent it",
    # F-037. Both were bare and unrecorded, which is what let the omissions in
    # the same sweep go unnoticed: nothing distinguished "considered and left
    # alone" from "never looked at".
    ("RecordAttribution", "source"):            "same field as AuditItem.source -- the caller's own metadata label, free text",
    ("OpenAIErrorDetail", "code"):              "the proxy's OpenAI-shaped vocabulary, assembled from literals; not the error catalog",
}


def _published_enum(schemas: dict, model: str, prop: str):
    """The enum an integrator actually sees, however the property is expressed.

    An optional field is emitted as `anyOf: [{...}, {type: null}]`, so the enum
    sits one level down. Reading only the top level would report `None` for every
    nullable field and quietly pass.
    """
    spec = schemas[model]["properties"][prop]
    if "enum" in spec:
        return spec["enum"]
    for branch in spec.get("anyOf", []):
        if "enum" in branch:
            return branch["enum"]
    return None


def _assert_published(expected: dict) -> None:
    """Compare the ARTIFACT against the declared vocabulary, one family's worth."""
    import api.v1.schemas.response as R

    schemas = _committed()["components"]["schemas"]
    wrong = []
    for (model, prop), vocab in sorted(expected.items()):
        published = _published_enum(schemas, model, prop)
        want      = getattr(R, vocab)
        if published != want:
            wrong.append(f"{model}.{prop}: published {published}, expected {vocab}={want}")

    assert not wrong, "published allowed values do not match the declared vocabulary:\n  " + "\n  ".join(wrong)


def test_the_ai_family_publishes_its_allowed_values():
    """Phase C / F-030 Option B, first family.

    Read from `docs/openapi.json`, not the models: an enum that exists on a
    Python field but never reaches the artifact has not been published, and the
    artifact is what a code generator consumes.

    THIS ASSERTS SCHEMA METADATA ONLY. It says nothing about what values exist in
    `audit_logs` or `proxy_interactions`, and it must not be read as evidence
    that historical rows conform -- six of these fields are read back from
    `VARCHAR` columns written by earlier builds. That is precisely why the
    vocabulary is published without being enforced, and why Option A (typing the
    fields as enums) stays blocked.
    """

    _assert_published(_AI_FAMILY_ENUMS)


def test_the_published_vocabularies_match_their_source_of_truth():
    """`api/v1/schemas/response.py` imports nothing, by design, so its vocabulary
    lists are MIRRORS rather than derivations. A mirror that nobody checks is a
    copy that drifts, so each one is compared against the layer that actually
    produces the value."""
    import api.v1.schemas.response as R
    from api.v1.endpoints import proxy as P
    from domain.enums import (
        DecisionType,
        DetectionMode,
        ExecutionMode,
        InputSource,
        RiskLevel,
    )
    from engine.proxy.router import SUPPORTED_PROVIDERS

    assert R.DECISIONS        == [d.value for d in DecisionType]
    assert R.SEVERITIES       == [r.value for r in RiskLevel]
    assert R.DETECTION_MODES  == [d.value for d in DetectionMode]
    assert R.EXECUTION_MODES  == [e.value for e in ExecutionMode]
    assert R.INPUT_SOURCES    == [i.value for i in InputSource]
    assert sorted(R.PROXY_PROVIDERS) == sorted(SUPPORTED_PROVIDERS)
    assert sorted(R.EXECUTION_STATUSES) == sorted({
        P.STATUS_SUCCESS, P.STATUS_BLOCKED, P.STATUS_OUTPUT_BLOCKED,
        P.STATUS_FAILED, P.STATUS_TIMEOUT,
    })

    from engine.scoring.confidence import get_confidence_band
    assert sorted(set(R.CONFIDENCE_BANDS)) == sorted({get_confidence_band(c) for c in (0.9, 0.5, 0.1)})

    from domain.enums import ThreatCategory
    assert R.THREAT_CATEGORIES == [t.value for t in ThreatCategory]

    # `policy_source` is three values from the resolver plus one the scan route
    # writes on a cache hit, so it is checked against both producers.
    from services.policy_resolver import determine_policy_source
    resolver = {
        determine_policy_source(None, None),
        determine_policy_source({"x": 1}, None),
        determine_policy_source(None, {"x": 1}),
    }
    assert resolver <= set(R.POLICY_SOURCES), sorted(resolver - set(R.POLICY_SOURCES))
    assert "cache" in R.POLICY_SOURCES

    # `primary_reason` has no single constant to mirror -- the values are returned
    # as literals by two modules. Compare against the literals themselves so a new
    # reason cannot appear without this list being updated.
    import pathlib
    import re
    produced = set()
    for mod in ("engine/scoring/primary_reason.py", "engine/guardrails/output_guard.py"):
        text = pathlib.Path(mod).read_text(encoding="utf-8")
        produced |= set(re.findall(r'return "([A-Z_]+)"', text))
        produced |= set(re.findall(r'primary_reason\s*=\s*"([A-Z_]+)"', text))
        produced |= set(re.findall(r'^\s*"([A-Z_]+_DETECTOR)":', text, re.MULTILINE))
    assert produced <= set(R.PRIMARY_REASONS), (
        f"a reason is produced but not published: {sorted(produced - set(R.PRIMARY_REASONS))}"
    )


def test_the_excluded_fields_are_not_enumerated():
    """The audit's deliberate exceptions, held open.

    Publishing a vocabulary for these would be a claim the API cannot keep, and
    the failure mode is silent: someone tidying "inconsistent" fields would add
    an enum and nothing else would object.
    """
    schemas = _committed()["components"]["schemas"]
    wrong = [
        f"{model}.{prop} was enumerated, but {why}"
        for (model, prop), why in sorted(_NEVER_ENUMERATED.items())
        if _published_enum(schemas, model, prop) is not None
    ]
    assert not wrong, "\n  ".join(wrong)


def test_the_audit_family_publishes_its_allowed_values():
    """Phase C / F-030 Option B, audit family.

    ALL ELEVEN ARE PERSISTED -- every value is read back from a `VARCHAR` column
    in `audit_logs`, or joined from `proxy_interactions`. This test asserts the
    published SCHEMA and nothing else. It is not evidence that stored rows hold
    only these values, and it must never be turned into that: the reason the
    vocabulary is published without being enforced is precisely that nobody can
    make that claim from the repository.
    """
    _assert_published(_AUDIT_FAMILY_ENUMS)


def test_publishing_a_vocabulary_did_not_make_the_runtime_reject_anything():
    """The property that distinguishes Option B from Option A.

    An `enum` in the schema is documentation. If one of these fields had quietly
    become an Enum or a Literal, a value outside the list would raise instead of
    serialising -- and for the persisted fields that would turn a historical row
    into a 500 rather than a read. So the permissiveness is asserted, on one
    field from each family, rather than assumed from the type annotation.
    """
    import api.v1.schemas.response as R

    assert R.AssessmentLayer(name="rule", decision="A_NEW_DECISION").decision == "A_NEW_DECISION"
    assert R.TopThreat(category="A_NEW_CATEGORY", count=1).category == "A_NEW_CATEGORY"


def test_the_proxy_interactions_family_publishes_its_allowed_values():
    """Phase C / F-030 Option B, proxy-interactions family.

    All seven are persisted, read back from `proxy_interactions`. This asserts
    the published SCHEMA only. It is not evidence about stored rows, and the
    reason the vocabulary is published rather than enforced is that nobody can
    make that claim from the repository.

    `input_attack_type` is included after tracing rather than by resemblance: the
    proxy sets it to `input_threats[0]`, and `input_threats` is
    `[t.value for t in gd.threats]` over a `list[ThreatCategory]`. It is a scalar,
    so it takes scalar metadata cleanly -- unlike the threat ARRAYS beside it.
    """
    _assert_published(_PROXY_INTERACTION_FAMILY_ENUMS)


def test_the_detail_model_inherits_the_published_vocabulary():
    """`ProxyInteractionDetail` extends `ProxyInteraction`, so it gets the
    metadata by inheritance rather than by its own declaration. Asserted
    directly: flattening the models later would be an easy way to publish a
    detail schema that quietly says less than the list schema."""
    schemas = _committed()["components"]["schemas"]
    for prop in ("input_decision", "input_primary_reason", "input_attack_type",
                 "provider", "execution_status", "output_decision", "output_primary_reason"):
        assert _published_enum(schemas, "ProxyInteraction", prop) == \
               _published_enum(schemas, "ProxyInteractionDetail", prop), prop


def test_the_proxy_interaction_runtime_still_accepts_an_unknown_value():
    """Option B, on the family whose fields are most exposed to historical rows.

    `execution_status` is the sharpest case: the test fixtures in this repository
    write `completed`, which production never writes and the published vocabulary
    does not contain. That value must still round-trip, because the schema
    documents and does not enforce.
    """
    import api.v1.schemas.response as R

    # Every field is required, including the nullable ones -- absence and null are
    # different in this contract, so the writer must state which it means.
    row = R.ProxyInteraction(
        id="1", trace_id="tr-1", created_at=None, key_id=None, user_id=None,
        input_decision="ALLOW", input_primary_reason="NO_THREAT_DETECTED",
        input_confidence=1.0, input_threats=[], input_attack_type=None,
        provider=None, model=None, provider_latency_ms=None,
        execution_status="completed",
        output_decision=None, output_primary_reason=None, output_confidence=None,
        output_threats=[], behavior_flag=None, output_flags=None,
        total_latency_ms=1,
    )
    assert row.execution_status == "completed"
    assert row.model_dump()["execution_status"] == "completed"   # and it round-trips


def test_the_chat_family_publishes_its_allowed_values():
    """Phase C / F-030 Option B, chat family.

    NOTHING HERE IS PERSISTED. `ChatCompletionMeta` is built per request from the
    live gateway result, and the rest of the body from the provider's reply, so
    the historical-row caveat that governs the other families does not apply.
    Option B is still the right shape: the values are computed, but `provider`
    and `finish_reason` come from outside this API.
    """
    _assert_published(_CHAT_FAMILY_ENUMS)


def test_the_chat_meta_vocabularies_are_subsets_of_their_parents():
    """The narrowing is a claim, so it is checked rather than trusted.

    `CHAT_META_DECISIONS` and `CHAT_META_STATUSES` must stay strict subsets of the
    vocabularies the other families publish. A value appearing here but not in the
    parent would mean the chat body reports something no other surface can.
    """
    import api.v1.schemas.response as R

    assert set(R.CHAT_META_DECISIONS) < set(R.DECISIONS)
    assert set(R.CHAT_META_STATUSES)  < set(R.EXECUTION_STATUSES)
    assert "BLOCK" not in R.CHAT_META_DECISIONS
    assert R.CHAT_META_STATUSES == ["SUCCESS"]


def test_the_chat_narrowing_still_rests_on_the_route_returning_early():
    """What makes the narrow vocabulary true, pinned at the producer.

    Three lines in `proxy.py` are the whole argument: a blocked input returns, a
    blocked output returns, and the status is assigned unconditionally just before
    the success body is built. Remove any one and the published vocabulary becomes
    a lie, with nothing else to notice.
    """
    import pathlib

    src = pathlib.Path("api/v1/endpoints/proxy.py").read_text(encoding="utf-8")
    for guarantee in (
        'if input_decision == "BLOCK":',
        'if output_decision == "BLOCK":',
        "execution_status = STATUS_SUCCESS",
    ):
        assert guarantee in src, (
            f"{guarantee!r} is gone from proxy.py, so the chat body may now carry a "
            "state the published vocabulary excludes. Re-derive CHAT_META_* before "
            "deleting this assertion."
        )


def test_a_nullable_field_publishes_its_enum_on_the_string_branch():
    """Placement, not just values -- and the reason the metadata is a callable.

    `json_schema_extra={"enum": [...]}` lands the keyword as a SIBLING of `anyOf`.
    JSON Schema ANDs siblings, so `null` satisfies the `anyOf` and then fails the
    `enum`: the published contract would say a nullable field cannot be null,
    while the runtime happily returns null. Every nullable enumerated field is
    checked, because the failure is invisible in the values.
    """
    schemas = _committed()["components"]["schemas"]
    misplaced = [
        f"{model}.{prop}"
        for model, schema in schemas.items()
        for prop, spec in schema.get("properties", {}).items()
        if "anyOf" in spec and "enum" in spec
    ]
    assert not misplaced, (
        "enum sits beside anyOf on these nullable fields, so null is no longer "
        f"valid for them in the published schema: {misplaced}"
    )

    # And the positive case: a known nullable field keeps its null branch.
    out = schemas["AuditItem"]["properties"]["output_decision"]
    assert any(b.get("type") == "null" for b in out["anyOf"])
    assert any(b.get("enum") for b in out["anyOf"])


def test_the_chat_runtime_still_accepts_an_unknown_value():
    """Option B on the narrowest vocabulary in the API: `execution_status`
    publishes exactly one value, and the field must still carry any string."""
    import api.v1.schemas.response as R

    meta = R.ChatCompletionMeta(
        trace_id="req_x", decision="BLOCK", input_primary_reason="WHATEVER",
        input_confidence=1.0, input_was_sanitized=False, output_decision=None,
        output_was_sanitized=False, execution_status="TIMEOUT",
        provider="something-new", model="m", total_latency_ms=1,
    )
    assert meta.execution_status == "TIMEOUT"
    assert meta.model_dump()["decision"] == "BLOCK"


def test_the_keys_family_publishes_its_allowed_values():
    """Phase C / F-030 Option B, keys family.

    Both fields are persisted in `api_keys.key_type`, a `VARCHAR(20)` with a
    server default of `live`. Schema metadata only: this says nothing about the
    values stored on any deployment, and Option A remains blocked for exactly
    that reason.
    """
    _assert_published(_KEYS_FAMILY_ENUMS)


def test_the_key_type_vocabulary_matches_its_producer():
    """`KeyType` lives in the endpoint module rather than `domain.enums`, and it
    is what actually gates the write path -- `CreateKeySchema.key_type` is typed
    with it, so an unknown value is a 422 before anything is stored."""
    import api.v1.schemas.response as R
    from api.v1.endpoints.keys import KeyType

    assert R.KEY_TYPES == [k.value for k in KeyType]


def test_the_key_type_fields_are_not_nullable_so_the_enum_sits_at_the_top_level():
    """The other half of F-032, asserted positively.

    Every other enumerated field in the API is nullable somewhere, so the global
    placement test only ever exercises `_allowed`'s `anyOf` branch. These two are
    non-nullable, and pin the fallback: the enum belongs directly on the string
    schema, with no union wrapper invented around it.
    """
    schemas = _committed()["components"]["schemas"]
    for model in ("ApiKeyCreated", "ApiKeyListItem"):
        spec = schemas[model]["properties"]["key_type"]
        assert spec.get("type") == "string", spec
        assert "anyOf" not in spec, f"{model}.key_type gained a union it does not have"
        assert spec.get("enum") == ["live", "trial"]


def test_the_keys_runtime_still_accepts_an_unknown_key_type():
    """A row written before `key_type` existed reads back through this model. The
    read path coerces a missing value to `live`, but a stored value outside the
    vocabulary is passed through -- so the model must carry it rather than raise.
    """
    import api.v1.schemas.response as R

    created = R.ApiKeyCreated(
        key_id="k1", name="n", api_key="wsk_live_x", key_type="legacy_tier",
        app_id=None, dept_id=None, tenant_id=None,
        created_at="2026-01-01T00:00:00Z", expires_at=None,
    )
    assert created.key_type == "legacy_tier"
    assert created.model_dump()["key_type"] == "legacy_tier"


def test_the_health_family_publishes_its_allowed_values():
    """Phase C / F-030 Option B, health and capabilities family.

    NOTHING HERE IS PERSISTED. Every value is computed while answering the
    request -- a probe result, a policy-origin ternary, or the plugin registry --
    so the historical-row caveat does not apply. Option B is still the right
    shape: these are documentation, and a probe that grows a state should not
    start failing responses.
    """
    _assert_published(_HEALTH_FAMILY_ENUMS)


def test_the_health_vocabularies_match_their_producers():
    """Each vocabulary against the literals `health.py` and `capabilities.py`
    actually emit. Read from source because these are inline literals rather than
    an enum or a module constant -- there is nothing else to compare against."""
    import pathlib
    import re

    import api.v1.schemas.response as R

    health = pathlib.Path("api/v1/endpoints/health.py").read_text(encoding="utf-8")
    caps   = pathlib.Path("api/v1/endpoints/capabilities.py").read_text(encoding="utf-8")

    assert '"status":  "ok"' in health,                    "the /health literal moved"
    assert '{"status": "alive"}' in health,                "the /health/live literal moved"
    assert '"ready" if all_ok else "degraded"' in health,  "the readiness ternary moved"
    assert '"ok"      if db_ok    else "unavailable"' in health
    assert '"ok"      if redis_ok else "unavailable"' in health
    assert '"enterprise" if caps else "oss"' in caps,      "the edition ternary moved"

    # The detector tiers: one default and one ternary, three values in total.
    detector = set(re.findall(r'_status\s*=\s*"(\w+)"', health))
    detector |= set(re.findall(r'"(\w+)" if \w+\.is_model_loaded\(\) +else +"(\w+)"', health)[0]
                    if re.findall(r'"(\w+)" if \w+\.is_model_loaded\(\) +else +"(\w+)"', health) else [])
    assert detector <= set(R.DETECTOR_CHECK_STATUSES), sorted(detector - set(R.DETECTOR_CHECK_STATUSES))

    # `Config*.source` is one ternary repeated per section, so the vocabulary is
    # shared rather than four look-alikes.
    sources = set(re.findall(r'"source": "(\w+)" if \w+ +else "(\w+)"', health))
    assert sources, "the Config*.source ternaries moved"
    for a, b in sources:
        assert {a, b} == set(R.CONFIG_SOURCES), (a, b)


def test_the_probe_vocabularies_are_not_merged():
    """Infrastructure and detector tiers report on different scales.

    A database is reachable or it is not; a detector additionally distinguishes
    loaded from running-without-its-model. Publishing one union would say a
    database can be `healthy`, which it cannot.
    """
    import api.v1.schemas.response as R

    assert "healthy" not in R.INFRA_CHECK_STATUSES
    assert "ok" not in R.DETECTOR_CHECK_STATUSES
    assert set(R.INFRA_CHECK_STATUSES) != set(R.DETECTOR_CHECK_STATUSES)
    assert "unavailable" in R.INFRA_CHECK_STATUSES and "unavailable" in R.DETECTOR_CHECK_STATUSES


def test_every_config_model_publishes_the_source_vocabulary():
    """All four, not a sample.

    `source` is produced by one ternary per section in `health.py`, so the four
    models share a vocabulary. The failure worth catching is publishing it on one
    model and treating the family as finished -- which reads as correct in any
    single-model check.
    """
    schemas = _committed()["components"]["schemas"]
    missing = [
        m for m in _CONFIG_SOURCE_MODELS
        if _published_enum(schemas, m, "source") != ["database", "environment"]
    ]
    assert not missing, f"these Config models do not publish the source vocabulary: {missing}"


def test_the_health_runtime_still_accepts_an_unknown_probe_value():
    """A probe that grows a state must not start failing the response. These are
    the narrowest vocabularies in the API -- one publishes a single value -- so
    permissiveness matters more here than anywhere else."""
    import api.v1.schemas.response as R

    checks = R.HealthChecks(database="quarantined", redis="ok",
                            tfidf_detector="healthy", transformer_detector="degraded")
    assert checks.database == "quarantined"
    assert R.HealthResponse(status="starting", version="1.0.0").status == "starting"
    assert R.CapabilitiesResponse(edition="community", capabilities=[]).model_dump()["edition"] == "community"


# ── Phase C / F-030 Option B: the agent-runs family ──────────────────────────
#
# This family added NO metadata, and that is the finding rather than an omission.
# `AgentRunResponse` has three properties: `run_id` (echoed straight back from the
# caller), `count` (an integer), and `scans` -- a list of `AuditItem`, the audit
# family's own model. Its vocabularies are published there and reach this
# operation by reference. Publishing them again would be a second source of truth
# for the same values.

def test_the_agent_run_turns_reference_the_audit_item_rather_than_copying_it():
    """The whole reason this family needed no work of its own.

    `scans.items` must stay a `$ref`. If the generator ever inlined `AuditItem`
    here -- a plausible outcome of restructuring the model -- this operation would
    get a private copy of the schema, and the enums published on the audit family
    would silently stop covering it. Nothing else would notice: the property names
    and types would be identical.
    """
    schemas = _committed()["components"]["schemas"]
    scans = schemas["AgentRunResponse"]["properties"]["scans"]

    assert scans.get("type") == "array", scans
    assert scans["items"] == {"$ref": "#/components/schemas/AuditItem"}, (
        "AgentRunResponse.scans no longer references AuditItem, so the audit "
        "vocabularies no longer reach GET /v1/agent-runs/{run_id}"
    )


def test_the_audit_vocabularies_reach_the_agent_run_operation():
    """Reachability, walked rather than assumed.

    Follows the operation's own 200 schema to `AgentRunResponse`, then to
    `AuditItem`, and checks the vocabularies are there -- which is what an
    integrator or a code generator actually resolves.
    """
    doc = _committed()
    schemas = doc["components"]["schemas"]

    ref = doc["paths"]["/v1/agent-runs/{run_id}"]["get"]["responses"]["200"] \
             ["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("/AgentRunResponse")

    item_ref = schemas["AgentRunResponse"]["properties"]["scans"]["items"]["$ref"]
    item = schemas[item_ref.rsplit("/", 1)[-1]]

    missing = [
        prop for (model, prop), _ in _AUDIT_FAMILY_ENUMS.items()
        if model == "AuditItem"
        and not (item["properties"][prop].get("enum")
                 or any(b.get("enum") for b in item["properties"][prop].get("anyOf", [])))
    ]
    assert not missing, (
        f"these audit vocabularies are not reachable from the agent-run scans: {missing}"
    )


def test_the_agent_run_envelope_has_no_vocabulary_of_its_own():
    """No new vocabulary was found here, and the absence is pinned.

    `run_id` is whatever the caller put in the path -- constrained only by the
    NUL rule from F-024 -- and `count` is an integer. If either ever gained an
    enum it would be a claim about caller input, so the exclusion is asserted
    rather than left to reviewer memory.
    """
    schemas = _committed()["components"]["schemas"]
    props = schemas["AgentRunResponse"]["properties"]

    assert _published_enum(schemas, "AgentRunResponse", "run_id") is None
    assert props["count"]["type"] == "integer"
    assert set(props) == {"run_id", "count", "scans"}, (
        f"AgentRunResponse gained a property that has not been classified: {sorted(props)}"
    )


def test_an_agent_run_still_round_trips_an_unknown_turn_value():
    """Option B end to end on the last family: a turn carrying a value outside the
    published vocabulary is still served, because the enum documents and does not
    enforce."""
    import api.v1.schemas.response as R

    turn = R.AuditItem(
        trace_id="req_1", timestamp="2026-01-01T00:00:00Z", tenant_id=None,
        decision="ESCALATE", output_decision=None, provider=None, model=None,
        primary_reason=None, risk_score=0.0, confidence=None, confidence_band=None,
        threats=[], input_hash="h", detection_mode="fast", execution_mode="scan_only",
        latency_ms=1.0, key_id=None, dept_id=None, dept_name=None, app_id=None,
        app_name=None, user_id=None, source=None, ip_address=None,
        attribution_verified=False, policy_source=None, input_length=1,
        severity="LOW", session_id=None, turn_index=None, run_id=None,
        input_source="user_prompt", record_hash=None, prev_hash=None,
    )
    run = R.AgentRunResponse(run_id="anything the caller sent", count=1, scans=[turn])

    assert run.scans[0].decision == "ESCALATE"
    assert run.model_dump()["scans"][0]["decision"] == "ESCALATE"


# ── Phase C / §17: field descriptions, by family ─────────────────────────────

_HEALTH_DESCRIBED_MODELS = [
    "HealthResponse", "LivenessResponse", "ReadinessResponse", "HealthChecks",
    "HealthConfigResponse", "ConfigThresholds", "ConfigDetectionLayers",
    "ConfigLLM", "ConfigRateLimit", "CapabilitiesResponse",
]


def test_the_health_family_describes_every_published_field():
    """§17 for the health and capabilities family, read from the artifact.

    Same reasoning as the settings guard: a description is documentation, so
    nothing at runtime notices when one is missing, and a field added later
    without one costs nothing and fails no other check.

    Scoped to this family. The remaining families are converted in their own
    passes, and widening the list before then would fail for work that has not
    been done yet.
    """
    schemas = _committed()["components"]["schemas"]

    undescribed = [
        f"{name}.{prop}"
        for name in _HEALTH_DESCRIBED_MODELS
        for prop, spec in schemas[name]["properties"].items()
        if not (spec.get("description") or "").strip()
    ]

    assert not undescribed, (
        f"published health fields with no description: {undescribed}. "
        "Add one that says something the field name does not, or state here why "
        "the field is self-explanatory."
    )


def test_the_four_config_sections_describe_source_identically():
    """The gap the §19 health pass found and left for §17.

    `source` is produced by one ternary per section, so the four sections carry
    the same field with the same meaning. Only `ConfigThresholds` described it;
    the other three said nothing, which reads as though they differ. The wording
    is now shared, and this asserts it stays shared rather than drifting into
    four paraphrases of one sentence.
    """
    schemas = _committed()["components"]["schemas"]
    wording = {
        model: schemas[model]["properties"]["source"].get("description")
        for model in ("ConfigThresholds", "ConfigDetectionLayers",
                      "ConfigLLM", "ConfigRateLimit")
    }
    assert len(set(wording.values())) == 1, f"the four sections describe source differently: {wording}"
    assert wording["ConfigThresholds"], "the shared wording is empty"


def test_a_described_nested_model_keeps_its_reference():
    """Describing a nested field must not inline the model it points to.

    Five health fields point at another schema and now carry a description
    beside the `$ref`. This document is OpenAPI 3.1, where sibling keywords are
    honoured rather than ignored, and six pre-existing fields already do the
    same. What must not happen is the generator dropping the reference or
    wrapping it in `allOf`, which would give these operations a private copy of
    a shared schema.
    """
    schemas = _committed()["components"]["schemas"]
    for model, prop, target in (
        ("ReadinessResponse", "checks", "HealthChecks"),
        ("HealthConfigResponse", "thresholds", "ConfigThresholds"),
        ("HealthConfigResponse", "detection_layers", "ConfigDetectionLayers"),
        ("HealthConfigResponse", "llm", "ConfigLLM"),
        ("HealthConfigResponse", "rate_limit", "ConfigRateLimit"),
    ):
        spec = schemas[model]["properties"][prop]
        assert spec.get("$ref") == f"#/components/schemas/{target}", (model, prop, spec)
        assert "allOf" not in spec, f"{model}.{prop} gained an allOf wrapper"
        assert (spec.get("description") or "").strip(), f"{model}.{prop} lost its description"


_SCAN_DESCRIBED_MODELS = [
    "ScanResponse", "Assessment", "AssessmentLayer", "ScanProcessing", "ScanDebug",
    "ScanBatchResponse", "BatchItemResult", "BatchSummary",
    "RequestRecordResponse", "RecordProcessing", "RecordAttribution", "RecordProxyDetail",
]


def test_the_scan_family_describes_every_published_field():
    """§17 for the scan family: the two scan routes and the read-back.

    The largest family in the API, and the one an integrator meets first. Same
    reasoning as the settings and health guards -- a missing description costs
    nothing at runtime and fails no other check, so only a test notices.
    """
    schemas = _committed()["components"]["schemas"]

    undescribed = [
        f"{name}.{prop}"
        for name in _SCAN_DESCRIBED_MODELS
        for prop, spec in schemas[name]["properties"].items()
        if not (spec.get("description") or "").strip()
    ]

    assert not undescribed, (
        f"published scan fields with no description: {undescribed}. "
        "Add one that says something the field name does not, or state here why "
        "the field is self-explanatory."
    )


def test_the_read_back_reuses_the_scan_wording_for_the_same_field():
    """The read-back repeats the scan's own fields, and must describe them the
    same way.

    `GET /v1/ai/requests/{trace_id}` returns the persisted form of the decision
    the scan already reported. Where the two carry the same field, a reader
    comparing them should not have to work out whether two different sentences
    mean two different things.
    """
    schemas = _committed()["components"]["schemas"]
    scan = schemas["ScanResponse"]["properties"]
    back = schemas["RequestRecordResponse"]["properties"]

    for prop in ("decision", "risk_score", "primary_reason", "confidence",
                 "confidence_band", "threats"):
        assert scan[prop].get("description") == back[prop].get("description"), (
            f"ScanResponse.{prop} and RequestRecordResponse.{prop} describe the "
            "same value differently"
        )


_AUDIT_DESCRIBED_MODELS = ["AuditItem", "AuditLogsResponse", "AuditStatsResponse",
                           "SeverityCounts", "TopThreat"]


def test_the_audit_family_describes_every_published_field():
    """§17 for the audit family.

    `AuditItem` is worth more than its own two routes: `GET /v1/agent-runs/{run_id}`
    reaches it by `$ref`, so a field left undescribed here is undescribed on three
    published operations rather than two.
    """
    schemas = _committed()["components"]["schemas"]

    undescribed = [
        f"{name}.{prop}"
        for name in _AUDIT_DESCRIBED_MODELS
        for prop, spec in schemas[name]["properties"].items()
        if not (spec.get("description") or "").strip()
    ]

    assert not undescribed, (
        f"published audit fields with no description: {undescribed}. "
        "Add one that says something the field name does not, or state here why "
        "the field is self-explanatory."
    )


def test_the_audit_record_reuses_the_scan_wording_for_the_same_field():
    """The audit row and the scan read-back carry the same values.

    `GET /v1/audit/logs` and `GET /v1/ai/requests/{trace_id}` project the same
    persisted row through different models. Where a field means the same thing in
    both, it should not be explained twice in two voices -- a reader comparing the
    two responses would have to work out whether the difference is meaningful.
    """
    schemas = _committed()["components"]["schemas"]
    audit  = schemas["AuditItem"]["properties"]
    record = schemas["RequestRecordResponse"]["properties"]

    for prop in ("primary_reason", "risk_score", "confidence", "confidence_band",
                 "threats", "input_length", "session_id", "turn_index"):
        assert audit[prop].get("description") == record[prop].get("description"), (
            f"AuditItem.{prop} and RequestRecordResponse.{prop} describe the same "
            "value differently"
        )


_PROXY_DESCRIBED_MODELS = ["ProxyInteraction", "ProxyInteractionDetail",
                           "ProxyInteractionsResponse"]


def test_the_proxy_interaction_family_describes_every_published_field():
    """§17 for the proxy-interactions family.

    Both published schemas are checked, not just the base. The fields are
    declared once on `ProxyInteraction` and inherited, so a description reaches
    the detail schema only because the generator carries it there -- which is a
    property of the generator, not something the source guarantees.
    """
    schemas = _committed()["components"]["schemas"]

    undescribed = [
        f"{name}.{prop}"
        for name in _PROXY_DESCRIBED_MODELS
        for prop, spec in schemas[name]["properties"].items()
        if not (spec.get("description") or "").strip()
    ]

    assert not undescribed, (
        f"published proxy-interaction fields with no description: {undescribed}. "
        "Add one that says something the field name does not, or state here why "
        "the field is self-explanatory."
    )


def test_the_threat_arrays_are_described_without_claiming_an_item_vocabulary():
    """The arrays hold ThreatCategory values, and the schema does not say so.

    There is no item-schema convention in this repository, so §19 left the item
    enum unpublished rather than inventing one. The descriptions must therefore
    explain what the array holds WITHOUT the schema asserting a closed set --
    and the absence of that enum is asserted here so a later pass cannot add one
    on the strength of the wording alone.
    """
    schemas = _committed()["components"]["schemas"]
    for model in ("ProxyInteraction", "ProxyInteractionDetail"):
        for prop in ("input_threats", "output_threats"):
            spec = schemas[model]["properties"][prop]
            assert (spec.get("description") or "").strip(), f"{model}.{prop}"
            assert "enum" not in spec, f"{model}.{prop} gained an enum on the array"
            assert "enum" not in spec.get("items", {}), (
                f"{model}.{prop} gained an item enum without an agreed convention"
            )


def test_the_two_projections_of_a_proxy_column_agree():
    """`RecordProxyDetail` projects the same `proxy_interactions` columns into the
    scan read-back. Where both expose a column, they describe it the same way --
    otherwise a reader comparing the two responses has to decide whether the
    difference is meaningful."""
    schemas = _committed()["components"]["schemas"]
    proxy  = schemas["ProxyInteraction"]["properties"]
    record = schemas["RecordProxyDetail"]["properties"]

    for prop in ("model", "input_primary_reason", "input_confidence", "input_threats",
                 "input_attack_type", "output_primary_reason", "output_confidence",
                 "output_threats", "behavior_flag", "output_flags", "execution_status"):
        assert proxy[prop].get("description") == record[prop].get("description"), (
            f"ProxyInteraction.{prop} and RecordProxyDetail.{prop} describe the "
            "same column differently"
        )


def test_every_published_response_field_is_described():
    """§17 complete: the whole response surface, not one family at a time.

    The per-family guards above were each scoped to work that had been done, so
    none of them could catch a family nobody had started. This one derives the
    model set from `api.v1.schemas.response` itself, so a response model added
    later is covered the day it appears rather than the day someone remembers to
    add it to a list.

    REQUEST schemas are deliberately outside this check. Phase C is "enrich
    RESPONSE models" and the 336-field baseline was measured over that module;
    the request side is a separate scope question, recorded as F-033. Asserting
    it here would fail for work nobody has agreed to do.
    """
    import inspect

    from pydantic import BaseModel

    import api.v1.schemas.response as response_module

    response_models = {
        name for name, obj in vars(response_module).items()
        if inspect.isclass(obj) and issubclass(obj, BaseModel) and obj is not BaseModel
    }

    schemas = _committed()["components"]["schemas"]
    undescribed = [
        f"{name}.{prop}"
        for name, schema in schemas.items()
        if name in response_models
        for prop, spec in schema.get("properties", {}).items()
        if not (spec.get("description") or "").strip()
    ]

    assert not undescribed, (
        f"published response fields with no description: {undescribed}. "
        "§17 is complete for the response surface; a new field needs one too."
    )


def test_the_shared_error_envelope_describes_its_whole_contract():
    """The envelope is referenced by most operations, so a gap here is a gap
    everywhere.

    The split it documents is the point: `code`, `key`, `severity` and `params`
    are machine-readable, `message` is presentation, and `invalid_params` appears
    only where there is field detail. A client that reads `message` when it
    should branch on `code` is the failure this wording exists to prevent.
    """
    schemas = _committed()["components"]["schemas"]

    envelope = schemas["ErrorEnvelope"]["properties"]
    assert (envelope["error"].get("description") or "").strip()

    detail = schemas["ErrorDetail"]["properties"]
    for prop in ("code", "severity", "key", "params", "message", "trace_id", "invalid_params"):
        assert (detail[prop].get("description") or "").strip(), f"ErrorDetail.{prop}"


# ── F-035 / F-036: examples and the vocabularies they must agree with ─────────
#
# F-035 was a published example asserting `risk_level: "NONE"`, a value
# `RiskLevel` has never held. It survived Phase A, §17 and §19 because every
# check it could have failed was structural, and structurally it was fine: the
# field was a bare `str`, so both `model_validate` and full JSON-Schema
# validation passed on it. Confirmed by running them -- neither catches this.
#
# So the guard that matters is the one below that reads example values back
# against the DOMAIN ENUM. Structural validation is kept as well, for the
# classes it does catch, but on its own it is not a detector.

def _threat_categories():
    from domain.enums import ThreatCategory

    return {m.value for m in ThreatCategory}


_VOCAB_FIELDS = {
    # example key -> the source of truth its value must belong to
    "risk_level":        lambda: {m.value for m in _risk_level_enum()},
    "decision":          lambda: {"BLOCK", "SANITIZE", "ALLOW"},
    "confidence_band":   lambda: {"HIGH", "MEDIUM", "LOW"},
    "detection_mode":    lambda: {"fast", "full"},
    "execution_mode":    lambda: {"scan_only", "proxy"},
    # Array-valued and single-valued threat vocabularies. `input_attack_type`
    # is checked here rather than through the schema on purpose: it is the ONE
    # model where the vocabulary is not published (see the F-037 evidence), so
    # schema validation cannot see a wrong value.
    "threats":           _threat_categories,
    "input_threats":     _threat_categories,
    "output_threats":    _threat_categories,
    "input_attack_type": _threat_categories,
    "policy_source":     lambda: {"system_default", "department_override",
                                  "application_override"},
    "input_source":      lambda: {"user_prompt", "tool_output",
                                  "retrieved_document", "external_content",
                                  "agent_tool_call"},
    "tier":              lambda: {"trusted", "untrusted", "unknown"},
}


def _risk_level_enum():
    from domain.enums import RiskLevel

    return RiskLevel


def _published_examples(schemas: dict) -> list[tuple[str, dict]]:
    """Every model-level example in the artifact, as (model, value) pairs."""
    found = []
    for name, schema in schemas.items():
        for value in schema.get("examples", []):
            found.append((name, value))
    return found


def _published_field_examples(schemas: dict) -> list[tuple[str, str, object]]:
    """Every FIELD-level example, as (model, property, value) triples."""
    found = []
    for name, schema in schemas.items():
        for prop, spec in schema.get("properties", {}).items():
            for value in spec.get("examples", []):
                found.append((name, prop, value))
    return found


def _walk(value, path="", key=None):
    """Yield (key, leaf_value, path) for every scalar in a nested example.

    A list of scalars yields each ITEM under the list's own key, so
    `threats: ["PROMPT_INJECTION"]` is checked rather than skipped. Getting that
    wrong is how an array-valued vocabulary passes a guard that only reads
    dict leaves.
    """
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, (dict, list)):
                yield from _walk(v, f"{path}.{k}", k)
            else:
                yield k, v, f"{path}.{k}"
    elif isinstance(value, list):
        for i, v in enumerate(value):
            if isinstance(v, (dict, list)):
                yield from _walk(v, f"{path}[{i}]", key)
            else:
                yield key, v, f"{path}[{i}]"


def test_every_published_example_value_belongs_to_its_domain_enum():
    """F-035's actual detector.

    Mutation check: putting `"NONE"` back on the example's `risk_level` fails
    here, and fails ONLY here -- the model and schema guards below both pass on
    it, which is exactly why this test exists.
    """
    schemas = _committed()["components"]["schemas"]
    examples = _published_examples(schemas)
    assert examples, "no published examples found; this guard would pass vacuously"

    # field-level examples are inspected under their own property name, so a
    # bare string like `{"examples": ["PROMPT_INJECTIN"]}` is caught too
    fields = _published_field_examples(schemas)
    assert fields, "no field-level examples found; §18 regressed"
    for model, prop, value in fields:
        examples.append((f"{model}.{prop}", {prop: value}))

    wrong = []
    for model, example in examples:
        for key, value, path in _walk(example, model):
            source = _VOCAB_FIELDS.get(key)
            if source is None or not isinstance(value, str):
                continue
            allowed = source()
            if value not in allowed:
                wrong.append(f"{path} = {value!r}, not in {sorted(allowed)}")

    assert not wrong, (
        "a published example carries a value the API cannot emit:\n  "
        + "\n  ".join(wrong)
    )


def test_every_published_example_validates_against_its_own_model():
    """Kept for the classes it DOES catch -- a missing required field, a wrong
    type, a misspelled key. It does not catch a wrong enum member on a bare
    `str`, which is why it is not the only guard."""
    import api.v1.schemas.response as R

    schemas = _committed()["components"]["schemas"]
    for model, example in _published_examples(schemas):
        cls = getattr(R, model, None)
        if cls is None:
            continue
        cls.model_validate(example)


def test_examples_use_the_3_1_keyword_not_the_deprecated_singular():
    """This document is OpenAPI 3.1, whose Schema Object IS JSON Schema
    2020-12. `examples` (an array) is the keyword there; the singular `example`
    is an OpenAPI 3.0 carry-over that 3.1 deprecates."""
    schemas = _committed()["components"]["schemas"]

    singular = [name for name, schema in schemas.items() if "example" in schema]
    assert not singular, (
        f"these schemas use the deprecated singular `example`: {singular}. "
        "Use `examples: [{...}]`."
    )
    assert any("examples" in schema for schema in schemas.values()), (
        "no schema publishes `examples`; the mechanism regressed"
    )


def test_risk_level_publishes_its_vocabulary_without_enforcing_it():
    """F-036. The field was enum-backed from the start and published as a bare
    string, so it was never in F-030's inventory NOR in its recorded
    exclusions -- it was missed rather than considered."""
    import api.v1.schemas.response as R
    from domain.enums import RiskLevel

    schemas = _committed()["components"]["schemas"]
    published = schemas["Assessment"]["properties"]["risk_level"]

    # the artifact carries exactly the enum's members
    assert published["enum"] == R.RISK_LEVELS
    assert set(published["enum"]) == {m.value for m in RiskLevel}
    assert published["enum"] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    # non-nullable, so the enum sits at the top level rather than inside anyOf
    assert published["type"] == "string"
    assert "anyOf" not in published

    # and the description no longer names a fifth value that does not exist
    assert "NONE" not in published["description"]


def test_risk_level_stays_a_plain_string_at_runtime():
    """Option B publishes the vocabulary as METADATA. The field is still `str`:
    a value outside the list is accepted, exactly as before. If this ever fails,
    someone has turned documentation into fail-closed validation on a response
    model, which is how a persisted legacy value becomes a 500."""
    import api.v1.schemas.response as R

    layer = {"name": "rule_score", "decision": "ALLOW", "score": 0.0}
    assessment = R.Assessment(
        decision="ALLOW", risk_score=0.0, risk_level="SOMETHING_NEW",
        primary_reason=None, confidence=None, confidence_band=None,
        threats=[], layers=[R.AssessmentLayer(**layer)],
    )
    assert assessment.risk_level == "SOMETHING_NEW"


def test_the_error_envelope_publishes_the_catalog_vocabularies():
    """F-030, corrected inventory. `ErrorDetail` is reachable from most
    operations, so a caller branching on `code` gets the whole set or none."""
    import api.v1.schemas.response as R
    from errors.catalog import ERROR_CATALOG, ErrorCode

    schemas = _committed()["components"]["schemas"]

    code = schemas["ErrorDetail"]["properties"]["code"]
    assert code["enum"] == R.ERROR_CODES
    assert set(code["enum"]) == {c.value for c in ErrorCode}
    assert len(code["enum"]) == 26

    severity = schemas["ErrorDetail"]["properties"]["severity"]
    assert severity["enum"] == R.ERROR_SEVERITIES
    in_use = {
        m.severity.value if hasattr(m.severity, "value") else m.severity
        for m in ERROR_CATALOG.values()
    }
    assert set(severity["enum"]) == in_use, (
        "ERROR_SEVERITIES must list what the catalog actually carries. "
        "`ErrorSeverity` also defines INFO; no entry uses it, and publishing it "
        "would promise a value no response can hold."
    )


def test_the_openai_error_code_stays_out_of_the_catalog_vocabulary():
    """Deliberate. `OpenAIErrorDetail` is the proxy's OpenAI-shaped refusal and
    carries its own lowercase vocabulary (`input_blocked`,
    `invalid_model_format`, ...) assembled from literals at the call sites, not
    from a closed type. Sharing `ErrorDetail`'s catalog enum would be wrong in
    both directions."""
    schemas = _committed()["components"]["schemas"]
    published = schemas["OpenAIErrorDetail"]["properties"]["code"]

    assert "enum" not in published, (
        "OpenAIErrorDetail.code gained an enum. It is not the error catalog; "
        "if it is to be enumerated it needs its own audited vocabulary."
    )


def test_every_field_example_validates_against_its_own_property_schema():
    """§18's generic type guard.

    One check for all 48 rather than a test per field: an example that is the
    wrong type, or outside a published enum, fails against the property's own
    schema. Nested `$ref`s are resolved so an object-valued example is checked
    against the model it points at rather than skipped.
    """
    from jsonschema import Draft202012Validator

    document = _committed()
    schemas = document["components"]["schemas"]

    failures = []
    for model, prop, value in _published_field_examples(schemas):
        spec = dict(schemas[model]["properties"][prop])
        spec.pop("examples", None)
        # re-root $refs so the validator can resolve them locally
        spec = json.loads(
            json.dumps(spec).replace("#/components/schemas/", "#/$defs/")
        )
        spec["$defs"] = json.loads(
            json.dumps(schemas).replace("#/components/schemas/", "#/$defs/")
        )
        for error in Draft202012Validator(spec).iter_errors(value):
            failures.append(f"{model}.{prop} = {value!r}: {error.message}")

    assert not failures, "field examples that do not satisfy their own schema:\n  " + "\n  ".join(failures)


def test_no_example_is_attached_to_a_field_whose_enum_already_says_everything():
    """§18's selection rule, held to.

    An enum already publishes the complete domain, so an example there picks one
    member arbitrarily and tells a reader nothing new. This is what stops §18
    drifting into a coverage sweep.

    There is no exception list, deliberately. `RecordProxyDetail.input_attack_type`
    carries an example and looks like it should need one -- but its vocabulary is
    NOT published on that model (F-037 evidence), so it has no enum and this
    guard does not flag it. An allowlist entry for it would be dead weight that
    reads like a real exemption; verified by emptying it and watching this still
    pass.
    """
    schemas = _committed()["components"]["schemas"]

    both = []
    for model, prop, _ in _published_field_examples(schemas):
        spec = schemas[model]["properties"][prop]
        if any("enum" in b for b in (spec.get("anyOf") or [spec])):
            both.append(f"{model}.{prop}")

    assert not both, (
        f"these fields carry BOTH an enum and an example: {both}. The enum "
        "already states the whole domain; see the §18 selection rule."
    )


def test_a_vocabulary_published_on_one_projection_is_published_on_all_of_them():
    """F-037's guard, and the one §19's per-family shape needed from the start.

    §19 ran one FAMILY per pass, but a persisted column is often projected by
    more than one model -- `input_attack_type` is read by both
    `ProxyInteraction` and `RecordProxyDetail`, `policy_source` by both
    `AuditItem` and `RecordProcessing`. A property enumerated in the family
    being worked stayed bare everywhere else, and nothing failed.

    Name-based on purpose. The Enum-derived sweep that found F-036 structurally
    could not find these: five of the six read from persisted columns rather
    than from an `Enum` member, so no amount of producer analysis reaches them.
    Two methods, two blind spots; this closes the second.

    A field that SHOULD stay bare goes in `_NEVER_ENUMERATED` with its reason,
    which is what makes "deliberately excluded" distinguishable from "missed".
    """
    import inspect

    from pydantic import BaseModel

    import api.v1.schemas.response as response_module

    response_models = {
        name for name, obj in vars(response_module).items()
        if inspect.isclass(obj) and issubclass(obj, BaseModel) and obj is not BaseModel
    }
    schemas = _committed()["components"]["schemas"]

    by_name: dict[str, list[tuple[str, tuple | None]]] = {}
    for model, schema in schemas.items():
        if model not in response_models:
            continue
        for prop in schema.get("properties", {}):
            enum = _published_enum(schemas, model, prop)
            by_name.setdefault(prop, []).append((model, tuple(enum) if enum else None))

    inconsistent = []
    for prop, rows in sorted(by_name.items()):
        enumerated = {m for m, e in rows if e}
        bare = {m for m, e in rows if not e}
        if not enumerated or not bare:
            continue
        unexplained = sorted(m for m in bare if (m, prop) not in _NEVER_ENUMERATED)
        if unexplained:
            inconsistent.append(
                f"{prop}: enumerated on {sorted(enumerated)} but bare on "
                f"{unexplained} with no recorded reason"
            )

    assert not inconsistent, (
        "a vocabulary is published on one projection and silently absent from "
        "another:\n  " + "\n  ".join(inconsistent)
        + "\n\nEither publish it on both, or record the exclusion in "
          "_NEVER_ENUMERATED with the reason it stays bare."
    )


def test_the_audit_rate_examples_describe_one_coherent_period():
    """A new class the other guards cannot see: examples that are each valid
    but incoherent TOGETHER.

    `block_rate`, `sanitize_rate` and `allow_rate` are `count / total` over one
    period (`audit.py:404-406`), so the three partition the same denominator and
    sum to 1. Three separately-plausible numbers that sum to 0.99 pass the type
    guard, pass the domain guard, and still describe a period that cannot exist
    -- which an integrator sizing a chart would discover the hard way.

    Scoped to the relationship that actually exists rather than generalised: a
    framework for declaring arbitrary field relationships would be more code
    than the one invariant this family has.
    """
    props = _committed()["components"]["schemas"]["AuditStatsResponse"]["properties"]

    rates = {
        name: props[name]["examples"][0]
        for name in ("block_rate", "sanitize_rate", "allow_rate")
    }
    total = sum(rates.values())
    assert abs(total - 1.0) < 1e-9, (
        f"the rate examples sum to {total}, not 1.0: {rates}. They partition one "
        "period's requests, so a caller cannot reconcile them."
    )

    for name, value in rates.items():
        assert 0.0 <= value <= 1.0, f"{name} example {value} is not a fraction"

    # the period bounds are ordered, and in the format the API emits
    assert props["period_from"]["examples"][0] < props["period_to"]["examples"][0]
    for bound in ("period_from", "period_to"):
        assert props[bound]["examples"][0].endswith("Z"), (
            f"{bound} example is not the ISO-8601 Z form `to_iso_z` produces"
        )


def test_the_threshold_examples_keep_block_above_sanitize():
    """A real relationship the property guards cannot see.

    `ThresholdsUpdateSchema` refuses an update where `block <= sanitize`
    (`settings.py`), so a pair of examples that inverts them describes a
    configuration the API would reject on write and never produce on read. Both
    projections of the pair are checked: the settings response and the health
    config view, which read the same two numbers.
    """
    schemas = _committed()["components"]["schemas"]

    pairs = [
        ("ThresholdsResponse", "block_threshold", "sanitize_threshold"),
        ("ConfigThresholds",   "block",           "sanitize"),
    ]
    for model, block_name, sanitize_name in pairs:
        props = schemas[model]["properties"]
        block    = props[block_name]["examples"][0]
        sanitize = props[sanitize_name]["examples"][0]
        assert block > sanitize, (
            f"{model}: block example {block} is not above sanitize {sanitize}; "
            "the settings validator refuses that pair"
        )
        for name, value in ((block_name, block), (sanitize_name, sanitize)):
            assert 0.0 < value <= 1.0, f"{model}.{name} example {value} is out of range"


def test_the_chat_id_example_is_derived_from_the_trace_id_example():
    """The proxy builds `id` as `wrapsec-{trace_id}` (`proxy.py:1531`).

    Two independently-plausible examples would let a reader think the id is the
    provider's completion id -- which is exactly the misreading the `wrapsec-`
    prefix exists to prevent, and which no per-property check can catch because
    each value is valid alone.
    """
    schemas = _committed()["components"]["schemas"]

    chat_id  = schemas["ChatCompletionResponse"]["properties"]["id"]["examples"][0]
    trace_id = schemas["ChatCompletionMeta"]["properties"]["trace_id"]["examples"][0]

    assert chat_id == f"wrapsec-{trace_id}", (
        f"chat id example {chat_id!r} is not `wrapsec-` + the meta trace_id "
        f"example {trace_id!r}; the two describe different calls"
    )


# ── Phase D / §23: the checks D1 measured, held as guards ─────────────────────
#
# D1 audited four properties of the committed artifact that nothing was watching.
# Three of them are structural and belong here. Each is written to catch the
# CLASS rather than the instance that prompted it, so a NEW field inherits the
# guard without anyone remembering to extend a list.


def _response_referenced(doc: dict) -> set[str]:
    """Every schema reachable from a response body, transitively.

    The request half of the document is deliberately excluded. `api_key` is
    published on two request bodies -- correctly, and marked `writeOnly` -- so a
    check that walked the whole document would fire on the one place the field
    belongs, and its absence there would be the actual defect.
    """
    schemas = doc["components"]["schemas"]
    found: set[str] = set()

    def collect(node) -> None:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if ref:
                name = ref.rsplit("/", 1)[-1]
                if name not in found:
                    found.add(name)
                    collect(schemas.get(name, {}))
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)

    for operations in doc.get("paths", {}).values():
        for operation in operations.values():
            if isinstance(operation, dict) and "responses" in operation:
                collect(operation["responses"])
    return found


def _response_properties(doc: dict):
    """(model, property, spec, required) for every property on a response model."""
    schemas = doc["components"]["schemas"]
    for name in sorted(_response_referenced(doc)):
        schema   = schemas.get(name, {})
        required = set(schema.get("required") or [])
        for prop, spec in (schema.get("properties") or {}).items():
            yield name, prop, spec, prop in required


# Columns that hold a credential, a key, or a chain secret. None may ever be a
# published response field. Listed by their ORM names so the second half of the
# guard can prove the column still exists: a rename that outran this list would
# otherwise leave a guard that passes because it is checking for nothing.
_NEVER_PUBLISHED_COLUMNS = {
    "password_hash", "key_hash", "secret_enc", "token_hash", "token_version",
    "old_secrets",
}

# Names that LOOK like the above but are published on purpose. Each is a value a
# consumer is meant to have, and each is recorded with the reason it is safe.
_PUBLISHED_HASH_FIELDS = {
    "input_hash":  "Handle on a prompt the storage mode did not retain. It is the "
                   "privacy-preserving reference, so withholding it would remove "
                   "the only way to correlate a scan with its input.",
    "prev_hash":   "The audit chain's link to the previous record. Publishing it "
                   "is what lets an auditor verify the chain independently.",
    "record_hash": "The audit record's own hash, for the same reason.",
}

_SENSITIVE_NAME = re.compile(
    r"password|passwd|secret|salt|private|credential|encrypted|cipher"
    r"|_hash$|^hash$|token_version|refresh_token|session_token|nonce",
    re.IGNORECASE,
)


def test_no_response_field_carries_a_credential_or_a_chain_secret():
    """A published response field whose name says credential is either a leak or
    a lie, and both are worth failing on.

    Mutation check: adding `password_hash` to any response model fails this.
    """
    doc = _committed()
    offenders = [
        f"{model}.{prop}"
        for model, prop, _spec, _req in _response_properties(doc)
        if _SENSITIVE_NAME.search(prop) and prop not in _PUBLISHED_HASH_FIELDS
    ]
    assert not offenders, (
        "response fields whose names indicate a credential or chain secret:\n  "
        + "\n  ".join(sorted(offenders))
        + "\nIf one is deliberate, record it in _PUBLISHED_HASH_FIELDS with the "
          "reason it is safe to publish."
    )


def test_the_credential_columns_this_guard_names_still_exist():
    """The guard above is only worth as much as its list. If a column is renamed
    and the list is not, the check quietly stops covering anything -- it would
    still pass while the renamed column was published under its new name."""
    from db import models

    source  = Path(models.__file__).read_text(encoding="utf-8")
    missing = [c for c in sorted(_NEVER_PUBLISHED_COLUMNS) if f"{c}:" not in source]
    assert not missing, (
        f"columns named by this guard no longer exist in db/models.py: {missing}. "
        "They were renamed or removed; update _NEVER_PUBLISHED_COLUMNS so the "
        "check keeps covering the real credential surface."
    )


def test_no_credential_column_name_appears_as_a_response_field():
    """The other direction, against the real column names rather than a pattern."""
    doc = _committed()
    published = {prop for _m, prop, _s, _r in _response_properties(doc)}
    leaked    = sorted(_NEVER_PUBLISHED_COLUMNS & published)
    assert not leaked, f"credential columns published as response fields: {leaked}"


# The vocabulary a description uses to say "this field may not be here". Held to
# a closed set on purpose: the guard below reads descriptions, so a new way of
# phrasing absence would silently opt a field out of it.
_ABSENCE_LANGUAGE = re.compile(r"\babsent\b|\bomitted\b|present only|not present",
                               re.IGNORECASE)


def test_optional_response_fields_are_exactly_the_ones_documented_as_absent():
    """`response_model_exclude_unset=True` is set on all 26 modelled routes, so
    OPTIONAL in the schema means "may be missing from the body" -- not "may be
    null". The two are different contracts and a consumer handles them
    differently.

    Held in both directions because each failure is real and neither is visible
    from one side alone:

      * required, yet described as absent-able -- the schema promises a field the
        runtime omits, which is the contract lie this phase exists to prevent;
      * optional, yet not described as absent-able -- the field can vanish and
        nothing tells the consumer, so absence reads as a bug in the caller.

    Mutation check: making `ScanResponse.debug` required fails the first half;
    removing "Present only" from its description fails the second.
    """
    doc = _committed()

    optional, documented = set(), set()
    for model, prop, spec, required in _response_properties(doc):
        if not required:
            optional.add(f"{model}.{prop}")
        if _ABSENCE_LANGUAGE.search(spec.get("description", "")):
            documented.add(f"{model}.{prop}")

    assert optional, "no optional response fields found; this guard would pass vacuously"

    assert not (documented - optional), (
        "response fields described as possibly absent but declared REQUIRED:\n  "
        + "\n  ".join(sorted(documented - optional))
        + "\nA required field is always emitted. Either the description is wrong "
          "or the field should carry a default."
    )
    assert not (optional - documented), (
        "response fields that may be absent but do not say so:\n  "
        + "\n  ".join(sorted(optional - documented))
        + "\nA consumer cannot tell an optional field from a missing one. State "
          "the condition in the description, using 'absent', 'omitted', "
          "'present only' or 'not present'."
    )


def test_health_ready_publishes_both_of_its_statuses():
    """The probe answers 503 when a dependency is down, and that is the status a
    consumer most needs declared -- an orchestrator reading only the 200 would
    treat the schema as saying the probe cannot fail."""
    doc = _committed()
    declared = set(doc["paths"]["/health/ready"]["get"]["responses"])
    assert {"200", "503"} <= declared, (
        f"/health/ready declares {sorted(declared)}; both 200 and 503 are reachable"
    )
