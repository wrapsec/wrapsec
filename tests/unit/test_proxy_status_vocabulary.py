# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""What the API EMITS is closed; what it ACCEPTS on read-back stays open.

The published vocabularies are OpenAPI `enum` METADATA on fields that remain
`str`, so the runtime cannot reject a value outside one. That is deliberate:
`test_the_proxy_interaction_runtime_still_accepts_an_unknown_value` requires a
stored row holding a retired value to keep reading back rather than becoming a
500. A historical row is not a contract violation.

But the two halves are different claims, and only one of them is open. The API
must never PRODUCE a value it does not publish, and nothing checked that. This
guards the producing half from the source: the closed set of literals the proxy
can write must be a subset of what the schema advertises.

Written against the module's constants rather than a list repeated here, so a
sixth status added to the producer is covered the moment it exists -- and fails
until it is published.
"""

from __future__ import annotations

import json
from pathlib import Path

_SCHEMA = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def _published(model: str, prop: str) -> set[str]:
    schemas = json.loads(_SCHEMA.read_text(encoding="utf-8"))["components"]["schemas"]
    spec = schemas[model]["properties"][prop]
    if "enum" in spec:
        return set(spec["enum"])
    for branch in spec.get("anyOf", []):
        if "enum" in branch:
            return set(branch["enum"])
    raise AssertionError(f"{model}.{prop} publishes no vocabulary")


def _emitted_statuses() -> dict[str, str]:
    """Every execution status the proxy can write, read off the module."""
    from api.v1.endpoints import proxy

    return {
        name: value
        for name, value in vars(proxy).items()
        if name.startswith("STATUS_") and isinstance(value, str)
    }


def test_every_status_the_proxy_can_emit_is_published():
    """A value the producer can write but the schema does not advertise is a
    contract the API breaks on its own success path -- and because the field is
    a bare `str`, nothing at runtime would notice."""
    emitted = _emitted_statuses()
    assert emitted, (
        "no STATUS_* constants found on the proxy module; this guard is reading "
        "the wrong thing and would pass no matter what the producer emits"
    )

    published = _published("ProxyInteraction", "execution_status")
    unpublished = {n: v for n, v in emitted.items() if v not in published}

    assert not unpublished, (
        "the proxy can emit execution statuses the schema does not publish:\n  "
        + "\n  ".join(f"{n} = {v!r}" for n, v in sorted(unpublished.items()))
        + f"\nPublished: {sorted(published)}"
    )


def test_the_inline_meta_publishes_the_same_statuses_it_can_carry():
    """The chat meta block declares its own, deliberately NARROWER list: a body
    carrying that block is a success, so it can never hold a blocked or failed
    status. Narrower is correct; carrying one it cannot publish is not."""
    meta = _published("ChatCompletionMeta", "execution_status")
    row  = _published("ProxyInteraction", "execution_status")

    assert meta <= row, (
        f"the chat meta publishes statuses the interaction record does not: "
        f"{sorted(meta - row)}"
    )
    assert meta, "the chat meta publishes no statuses at all"


def test_the_published_vocabulary_is_not_wider_than_what_can_be_emitted():
    """The other direction. A published value no producer can write advertises a
    state the API never reaches, which sends a consumer building a branch for
    something that will not arrive.

    This is the check that would have to be relaxed first if a status were
    retired from the producer but kept for historical rows -- and relaxing it
    deliberately is the point, rather than discovering the drift later.
    """
    emitted   = set(_emitted_statuses().values())
    published = _published("ProxyInteraction", "execution_status")

    assert published <= emitted, (
        "the schema publishes execution statuses no producer can emit: "
        f"{sorted(published - emitted)}. Either a producer was removed and the "
        "vocabulary was not, or the value exists only in historical rows -- in "
        "which case say so here rather than leaving the two out of step."
    )
