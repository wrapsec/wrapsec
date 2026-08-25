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


# ── the two deliberate special cases ─────────────────────────────────────────

def test_audit_export_is_advertised_as_json_although_it_returns_csv():
    """A KNOWN MISREPRESENTATION, pinned rather than asserted as correct.

    The route returns CSV, and it is a deliberate non-model exception. But a
    FastAPI route with no response_model still gets a default 200 of
    `application/json` with an empty schema, so the published contract currently
    tells a generator to expect JSON here. Nothing breaks today -- an empty schema
    constrains nothing -- but the media type is wrong.

    Pinned so the state is visible and so fixing it (a `responses=` entry naming
    text/csv) fails this test and prompts an update, instead of being mistaken for
    an unrelated schema diff. Not fixed here: this pass changes no route.
    """
    spec = _committed()
    ok = spec["paths"]["/v1/audit/export"]["get"]["responses"]["200"]
    content = ok.get("content") or {}

    assert list(content) == ["application/json"], (
        f"the advertised media types for audit/export changed: {list(content)}. "
        "If text/csv was declared, this known misrepresentation is fixed -- "
        "update this test to assert the corrected contract."
    )
    assert content["application/json"]["schema"] == {}, (
        "audit/export now advertises a non-empty JSON schema; it returns CSV"
    )


def test_chat_completions_is_present_and_not_forced_into_the_normal_pattern():
    """The OpenAI-compatible route. Its body is provider-shaped and it answers
    through many constructed Response paths, so it must not be given the ordinary
    response model during the family conversion."""
    spec = _committed()
    assert "/v1/chat/completions" in spec["paths"]
    op = spec["paths"]["/v1/chat/completions"]["post"]
    ok = op["responses"].get("200", {})
    schema = (ok.get("content") or {}).get("application/json", {}).get("schema")
    assert schema in (None, {}), (
        "chat/completions advertises a response schema; its contract is the "
        "OpenAI-compatible shape and is verified separately"
    )
