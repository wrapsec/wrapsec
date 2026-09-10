# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
`docs/api.md` labels each endpoint PUBLIC or NOT PUBLIC. Those labels must agree
with the authoritative boundary, or they are worse than no labels at all.

The page documents both surfaces on purpose: the 28-operation integrator contract
and the operator, dashboard and first-run routes that are served but not
published. A reader tells them apart only by the label under each heading, so a
stale label tells them the opposite of the truth -- and nothing else would catch
it, because the labels were written once and no code reads them.

The failure this prevents is ordinary: a route moves into or out of the public
contract, `PUBLIC_ROUTES` and `include_in_schema` are updated together (the
OpenAPI tests force that much), and the documentation is forgotten.

`PUBLIC_ROUTES` in `test_response_model_enforcement.py` is the single definition
and is imported, never restated. A second copy of the list here would drift from
the first, and both tests would keep passing while disagreeing.

MATCHING RULES, and why each is needed:

  * only a level-3 heading counts (`### GET /v1/...`). Prose mentioning a path,
    and there is a great deal of it, is not an endpoint declaration;
  * fenced code blocks are skipped entirely -- request and response examples are
    full of `POST /v1/...` lines;
  * path parameters are compared by POSITION, not by name: the page writes
    `/v1/keys/{id}` where the route declares `/v1/keys/{key_id}`. Both normalize
    to `/v1/keys/{}`;
  * a query string on a documented path is ignored;
  * comparison is by set, so the order of sections in the page is irrelevant.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.unit.test_response_model_enforcement import PUBLIC_ROUTES

_DOC = Path(__file__).resolve().parents[2] / "docs" / "api.md"

_HEADING = re.compile(r"^### (GET|POST|PUT|PATCH|DELETE) (\S+)")
_PUBLIC_LABEL     = "*PUBLIC -"
_NON_PUBLIC_LABEL = "*NOT PUBLIC -"


def _normalize(path: str) -> str:
    """Compare paths by shape: parameter NAMES differ between the page and the
    route table, parameter POSITIONS do not."""
    return re.sub(r"\{[^}]*\}", "{}", path.split("?")[0].rstrip("/"))


def _documented() -> dict[tuple[str, str], str | None]:
    """Every endpoint heading in the page, mapped to its label.

    The label is the first non-blank line after the heading, and is None when
    that line is not a label at all -- an unlabelled endpoint is a gap in the
    boundary, not a pass.
    """
    lines = _DOC.read_text(encoding="utf-8").splitlines()
    found: dict[tuple[str, str], str | None] = {}
    in_fence = False

    for index, line in enumerate(lines):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue

        match = _HEADING.match(line)
        if not match:
            continue

        label = None
        for following in lines[index + 1:]:
            if not following.strip():
                continue
            if following.startswith(_PUBLIC_LABEL):
                label = "PUBLIC"
            elif following.startswith(_NON_PUBLIC_LABEL):
                label = "NOT PUBLIC"
            break

        found[(_normalize(match.group(2)), match.group(1))] = label

    return found


def _normalized_public() -> set[tuple[str, str]]:
    normalized = {(_normalize(path), method) for path, method in PUBLIC_ROUTES}
    assert len(normalized) == len(PUBLIC_ROUTES), (
        "two public routes collapsed onto the same normalized path, so this "
        "comparison can no longer tell them apart: "
        f"{len(PUBLIC_ROUTES)} routes, {len(normalized)} normalized"
    )
    return normalized


def test_every_public_route_is_documented_and_labelled_public():
    """A published operation the page does not mark PUBLIC is one an integrator
    cannot tell is part of the contract."""
    documented = _documented()

    missing, mislabelled = [], []
    for key in sorted(_normalized_public()):
        path, method = key
        if key not in documented:
            missing.append(f"{method} {path}")
        elif documented[key] != "PUBLIC":
            mislabelled.append(f"{method} {path} (labelled {documented[key]})")

    assert not missing, (
        f"public operations with no heading in docs/api.md: {missing}. "
        "Every published operation must be documented."
    )
    assert not mislabelled, (
        f"public operations documented but not labelled PUBLIC: {mislabelled}. "
        "The page and PUBLIC_ROUTES disagree about the contract boundary."
    )


def test_nothing_outside_the_public_surface_is_labelled_public():
    """The direction that actually misleads: a dashboard or operator route
    presented as part of the integrator contract."""
    public = _normalized_public()

    wrong = sorted(
        f"{method} {path}"
        for (path, method), label in _documented().items()
        if label == "PUBLIC" and (path, method) not in public
    )
    assert not wrong, (
        f"documented as PUBLIC but outside the published contract: {wrong}. "
        "Either the route belongs to the public API -- a boundary decision, made "
        "by adding it to PUBLIC_ROUTES and to the schema -- or the label is wrong."
    )


def test_every_documented_endpoint_carries_a_label():
    """An unlabelled heading is how a new endpoint quietly joins neither side:
    the two tests above only compare what is labelled."""
    unlabelled = sorted(
        f"{method} {path}" for (path, method), label in _documented().items()
        if label is None
    )
    assert not unlabelled, (
        f"endpoint headings in docs/api.md with no PUBLIC / NOT PUBLIC label: "
        f"{unlabelled}"
    )


def test_the_page_documents_more_than_the_public_surface():
    """Guards the guard. If the parser stopped finding headings, or the page were
    trimmed to the public routes alone, every test above would pass while proving
    nothing about the non-public surface."""
    documented = _documented()
    assert len(documented) > len(PUBLIC_ROUTES), (
        f"docs/api.md yielded {len(documented)} endpoint headings against "
        f"{len(PUBLIC_ROUTES)} public routes; the page is expected to document "
        "the non-public surface as well"
    )
    assert any(label == "NOT PUBLIC" for label in documented.values()), (
        "no endpoint is labelled NOT PUBLIC, so the boundary is not being drawn"
    )


# ── the page's response examples against the schema ──────────────────────────
#
# The tests above hold the page's endpoint LIST to the boundary. Nothing held
# its CONTENT to anything: a response example could show a field the API does
# not send, and the only thing that would notice is a reader trying to use it.
#
# ASYMMETRIC ON PURPOSE. A field the page OMITS is not a defect -- most examples
# are deliberately partial, and requiring completeness would make every added
# field a documentation failure. A field the page SHOWS that the schema does not
# publish is drift by definition.

import json as _json

_SCHEMA_FILE = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"

# Bold markers that introduce a block. The page writes error examples as
# "**Input blocked (400):**" as often as "**Response 400:**", so ANY marker
# naming a 4xx/5xx ends the success context -- matching only the latter leaves
# the previous success marker in force and reads an error body as the success
# shape.
_STATUS_IN_MARKER = re.compile(r"^\*\*.*\b[45]\d\d\b")
_SUCCESS_MARKER   = re.compile(r"^\*\*(Response|Success)\b")
_INPUT_MARKER     = re.compile(r"^\*\*(Request|Query|Body|Header)")
_JSON_KEY         = re.compile(r'^\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*:', re.MULTILINE)


def _schema_properties() -> dict[tuple[str, str], set[str]]:
    """(method, normalized path) -> every property name reachable from its
    success response, including nested models and list items."""
    doc     = _json.loads(_SCHEMA_FILE.read_text(encoding="utf-8"))
    schemas = doc["components"]["schemas"]

    def walk(model: str, seen: set[str]) -> set[str]:
        if model in seen or model not in schemas:
            return set()
        seen.add(model)
        names: set[str] = set()
        for prop, spec in (schemas[model].get("properties") or {}).items():
            names.add(prop)
            ref = spec.get("$ref") or next(
                (b["$ref"] for b in spec.get("anyOf", []) if "$ref" in b), None)
            ref = ref or (spec.get("items") or {}).get("$ref")
            if ref:
                names |= walk(ref.rsplit("/", 1)[-1], seen)
        return names

    out: dict[tuple[str, str], set[str]] = {}
    for path, operations in doc.get("paths", {}).items():
        for method, operation in operations.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            ok = (operation.get("responses", {}).get("200")
                  or operation.get("responses", {}).get("201"))
            if not ok:
                continue
            ref = ((ok.get("content") or {}).get("application/json", {})
                   .get("schema", {}).get("$ref", ""))
            if ref:
                out[(method.upper(), _normalize(path))] = walk(ref.rsplit("/", 1)[-1], set())
    return out


def _documented_success_blocks():
    """Yield (method, normalized path, block text) for success-response examples.

    Skipped blocks still have their fences tracked: treating a skipped opening
    fence as absent makes the NEXT closing fence read as an opening one, and
    every block after it inverts.
    """
    endpoint: tuple[str, str] | None = None
    in_success = False
    in_fence   = False
    capturing  = False
    block: list[str] = []

    for line in _DOC.read_text(encoding="utf-8").splitlines():
        if not in_fence:
            heading = _HEADING.match(line)
            if heading:
                endpoint   = (heading.group(1), _normalize(heading.group(2)))
                in_success = False
                continue
            if line.startswith("#"):
                endpoint = None
            if _STATUS_IN_MARKER.match(line):
                in_success = False
                continue
            if _SUCCESS_MARKER.match(line):
                in_success = True
                continue
            if _INPUT_MARKER.match(line):
                in_success = False
                continue

        if line.strip().startswith("```"):
            if not in_fence:
                in_fence  = True
                capturing = bool(endpoint) and in_success
                block     = []
            else:
                if capturing and endpoint:
                    yield endpoint[0], endpoint[1], "\n".join(block)
                in_fence  = capturing = False
            continue

        if capturing:
            block.append(line)


def test_the_page_shows_no_response_field_the_schema_does_not_publish():
    """Documentation drift, in the direction that misleads a reader.

    Mutation check: adding `"invented_field": 1` to any public endpoint's
    success example fails this.
    """
    properties = _schema_properties()

    checked = 0
    drift: dict[str, set[str]] = {}
    for method, path, text in _documented_success_blocks():
        known = properties.get((method, path))
        if known is None:
            continue                       # not a public endpoint with a model
        keys = set(_JSON_KEY.findall(text))
        if not keys:
            continue
        checked += 1
        unknown = keys - known
        if unknown:
            drift.setdefault(f"{method} {path}", set()).update(unknown)

    assert checked >= 10, (
        f"only {checked} documented success examples were matched to a public "
        "endpoint; the page's markup changed and this guard is now reading "
        "almost nothing"
    )
    assert not drift, (
        "docs/api.md shows response fields the schema does not publish:\n  "
        + "\n  ".join(f"{e}: {sorted(v)}" for e, v in sorted(drift.items()))
        + "\nThe schema is the authority for a public operation, as the page "
          "itself states. Either the example is stale or the field was removed."
    )
