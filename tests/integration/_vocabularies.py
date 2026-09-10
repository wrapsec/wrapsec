# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Assert a real response body only carries values the schema publishes.

WHY THIS EXISTS. 77 response properties publish a vocabulary as OpenAPI `enum`
metadata while the field itself stays `str`. A bare `str` accepts anything, so a
writer emitting a value outside its published list passes model validation and
is served: the vocabulary is advertised and nothing enforces it. That is the one
mutation class the response models cannot catch, and this closes it from the
other side -- not by constraining the runtime, but by failing the build when a
writer emits something the contract never promised.

DRIVEN BY THE SCHEMA, NOT A LIST. The allowed values are read from
`docs/openapi.json` at call time and the walk follows the model's own
properties, so a field that GAINS a vocabulary is covered without touching this
file, and one that loses it stops being checked for the right reason. Nothing
here names a field.

Underscore-prefixed so pytest does not collect it as a test module.
"""

from __future__ import annotations

import json
from pathlib import Path

_SCHEMA = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def _schemas() -> dict:
    return json.loads(_SCHEMA.read_text(encoding="utf-8"))["components"]["schemas"]


def _enum_of(spec: dict) -> set[str] | None:
    """The vocabulary a property publishes, if it publishes one.

    A nullable field carries its enum on the string branch INSIDE `anyOf`, not
    beside it -- a sibling enum would be ANDed with the null branch and forbid
    null. Both placements are read here so the check does not silently skip
    every nullable field.
    """
    if "enum" in spec:
        return set(spec["enum"])
    for branch in spec.get("anyOf", []):
        if "enum" in branch:
            return set(branch["enum"])
    return None


def _ref_of(spec: dict) -> str | None:
    ref = spec.get("$ref")
    if ref:
        return ref.rsplit("/", 1)[-1]
    for branch in spec.get("anyOf", []):
        if "$ref" in branch:
            return branch["$ref"].rsplit("/", 1)[-1]
    return None


def _walk(node, model: str, schemas: dict, path: str, out: list[str]) -> None:
    schema = schemas.get(model)
    if not isinstance(schema, dict) or not isinstance(node, dict):
        return

    for prop, spec in (schema.get("properties") or {}).items():
        if prop not in node:
            continue                      # absent is legal; exclude_unset is on
        value = node[prop]
        here  = f"{path}.{prop}"

        allowed = _enum_of(spec)
        if allowed is not None and isinstance(value, str) and value not in allowed:
            out.append(f"{here} = {value!r} is not in {sorted(allowed)}")

        items = spec.get("items") or {}
        item_allowed = _enum_of(items) if items else None
        if item_allowed is not None and isinstance(value, list):
            for i, element in enumerate(value):
                if isinstance(element, str) and element not in item_allowed:
                    out.append(
                        f"{here}[{i}] = {element!r} is not in {sorted(item_allowed)}"
                    )

        nested = _ref_of(spec)
        if nested and isinstance(value, dict):
            _walk(value, nested, schemas, here, out)

        item_ref = items.get("$ref", "").rsplit("/", 1)[-1] if items else ""
        if item_ref and isinstance(value, list):
            for i, element in enumerate(value):
                _walk(element, item_ref, schemas, f"{here}[{i}]", out)


def assert_published_vocabulary(body: dict, model: str) -> None:
    """Fail if any value in `body` is outside the vocabulary its property
    publishes. Recurses into nested models and lists of models."""
    schemas = _schemas()
    assert model in schemas, f"{model} is not a published schema"

    failures: list[str] = []
    _walk(body, model, schemas, model, failures)
    assert not failures, (
        "a writer emitted a value outside the vocabulary the schema publishes "
        "for that field. The field is a bare `str`, so the runtime accepted it "
        "and the caller was served a value the contract never promised:\n  "
        + "\n  ".join(failures)
    )


def vocabulary_count(model: str) -> int:
    """How many properties reachable from `model` publish a vocabulary.

    Used to fail a check that would otherwise pass by walking nothing -- a body
    whose model published no enums at all would satisfy the assertion above
    vacuously.
    """
    schemas = _schemas()
    seen: set[str] = set()

    def count(name: str) -> int:
        if name in seen or name not in schemas:
            return 0
        seen.add(name)
        total = 0
        for spec in (schemas[name].get("properties") or {}).values():
            if _enum_of(spec) is not None:
                total += 1
            items = spec.get("items") or {}
            if items and _enum_of(items) is not None:
                total += 1
            nested = _ref_of(spec) or (items.get("$ref", "").rsplit("/", 1)[-1] if items else "")
            if nested:
                total += count(nested)
        return total

    return count(model)
