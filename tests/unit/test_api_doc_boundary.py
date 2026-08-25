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
