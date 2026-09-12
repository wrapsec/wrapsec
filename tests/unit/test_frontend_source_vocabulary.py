# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The input-source vocabulary, as the TypeScript surfaces spell it out.

`domain.enums.InputSource` is the vocabulary. Python consumers are held to it by
tests that import the enum directly. The Node SDK and the dashboard cannot: they
are TypeScript, so their copies are written by hand and nothing mechanical ties
them back.

That gap has already produced one defect. When `agent_tool_call` was added, eight
consumers were updated and one was missed, and the consistency check run at the
time passed because it enumerated the consumers someone thought of rather than
all of them. The miss was in Python and is now fenced; these two files are the
same shape with no fence at all.

What each drift would cost:

  * the Node SDK validates `input_source` CLIENT-side and throws before any
    request is made, so a missing value makes a label the API accepts
    unreachable through that client;
  * the dashboard maps a source to a human label and to a TRUST TIER. An unknown
    source falls back to title-case and to tier "unknown", so an untrusted
    origin would render as unclassified -- a wrong trust tier in a security UI.

READ FROM SOURCE, NOT FROM A BUILD. These assert what is committed, so they fail
in CI without installing Node or running a bundler.

A PARSE FAILURE IS A TEST FAILURE. If a declaration cannot be found, these fail
rather than skip: a fence that quietly matches nothing is how the drift it
guards gets through.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from config.settings import get_settings
from domain.enums import InputSource

_ROOT = Path(__file__).resolve().parents[2]

_NODE_CLIENT     = _ROOT / "sdk/node/src/client.ts"
_DASHBOARD_CONST = _ROOT / "dashboard/lib/constants.ts"


def _read(path: Path) -> str:
    assert path.exists(), (
        f"{path.relative_to(_ROOT)} is missing. If it moved, move this fence with "
        f"it rather than deleting the assertion."
    )
    return path.read_text(encoding="utf-8")


def _extract_block(source: str, declaration: str, closer: str, where: str) -> str:
    """The text between a declaration and its closing bracket.

    Deliberately narrow and deliberately loud: an unmatched declaration raises,
    because a fence that silently finds nothing passes forever.
    """
    start = source.find(declaration)
    assert start != -1, (
        f"could not find {declaration!r} in {where}. It was renamed or removed; "
        f"update this fence so the vocabulary stays tied to domain.enums."
    )
    end = source.find(closer, start)
    assert end != -1, f"{declaration!r} in {where} is not closed by {closer!r}"
    return source[start:end]


def _quoted(block: str) -> set[str]:
    return set(re.findall(r'"([a-z_]+)"', block))


def _expected() -> set[str]:
    return {member.value for member in InputSource}


# ---------------------------------------------------------------------------
# the Node SDK's client-side validator
# ---------------------------------------------------------------------------

def test_the_node_sdk_accepts_every_source_the_api_accepts():
    """`validateInputSource` throws before the request is built, so a value
    missing here is unreachable through that client even though the API takes
    it. That is precisely the defect the scan tool had."""
    block = _extract_block(
        _read(_NODE_CLIENT), "const VALID_INPUT_SOURCES = [", "]", "sdk/node/src/client.ts",
    )
    assert _quoted(block) == _expected(), (
        "sdk/node/src/client.ts VALID_INPUT_SOURCES and domain.enums.InputSource "
        "disagree. A Node caller cannot send a source this list omits."
    )


# ---------------------------------------------------------------------------
# the dashboard's labels and trust tiers
# ---------------------------------------------------------------------------

def test_the_dashboard_labels_every_source():
    """An unlabelled source falls back to title-case, which reads like a real
    label and hides that the UI does not know the value."""
    block = _extract_block(
        _read(_DASHBOARD_CONST),
        "export const CONTENT_SOURCE_LABELS", "}", "dashboard/lib/constants.ts",
    )
    labelled = set(re.findall(r"^\s*([a-z_]+):", block, re.MULTILINE))
    assert labelled == _expected(), (
        "dashboard/lib/constants.ts CONTENT_SOURCE_LABELS and "
        "domain.enums.InputSource disagree; unlabelled sources render through "
        "the title-case fallback"
    )


def test_the_dashboard_trust_tiers_match_the_shipped_defaults():
    """This one is NOT the whole enum, and must not be asserted as such.

    It mirrors `untrusted_input_sources` from settings, so `user_prompt` is
    absent by design. What matters is that it tracks that default: a source the
    backend treats as untrusted but the dashboard does not list renders as tier
    "unknown", which understates the risk to whoever is reading the page.
    """
    block = _extract_block(
        _read(_DASHBOARD_CONST),
        "const UNTRUSTED_CONTENT_SOURCES = new Set(", ")", "dashboard/lib/constants.ts",
    )
    get_settings.cache_clear()
    expected = set(get_settings().untrusted_input_sources)

    assert _quoted(block) == expected, (
        "dashboard/lib/constants.ts UNTRUSTED_CONTENT_SOURCES and the shipped "
        "untrusted_input_sources default disagree; a source the backend judges "
        "more strictly would display as unclassified"
    )


def test_every_source_is_either_trusted_or_untrusted_in_the_dashboard():
    """No enum member may be absent from both dashboard sets.

    Catches the case where a new source is labelled but never classified, which
    the two tests above would each pass individually.
    """
    source = _read(_DASHBOARD_CONST)
    untrusted = _quoted(_extract_block(
        source, "const UNTRUSTED_CONTENT_SOURCES = new Set(", ")",
        "dashboard/lib/constants.ts",
    ))
    trusted = _quoted(_extract_block(
        source, "const TRUSTED_CONTENT_SOURCES", ")", "dashboard/lib/constants.ts",
    ))

    unclassified = _expected() - untrusted - trusted
    assert not unclassified, (
        f"{sorted(unclassified)} appear in no dashboard trust set, so they render "
        f"as tier 'unknown' regardless of how the backend classifies them"
    )


# ---------------------------------------------------------------------------
# the fence itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("path", "declaration", "closer"),
    [
        (_NODE_CLIENT,     "const VALID_INPUT_SOURCES = [",             "]"),
        (_DASHBOARD_CONST, "export const CONTENT_SOURCE_LABELS",        "}"),
        (_DASHBOARD_CONST, "const UNTRUSTED_CONTENT_SOURCES = new Set(", ")"),
        (_DASHBOARD_CONST, "const TRUSTED_CONTENT_SOURCES",             ")"),
    ],
)
def test_each_declaration_is_still_found(path, declaration, closer):
    """Pins that the parsing still matches something.

    Without this, renaming a constant would make every assertion above stop
    examining anything while continuing to report green.
    """
    block = _extract_block(_read(path), declaration, closer, str(path.name))
    assert _quoted(block) or re.search(r"^\s*[a-z_]+:", block, re.MULTILINE), (
        f"{declaration!r} was located but no source values were parsed from it"
    )
