# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
`NOT_FOUND.params.resource` is a machine token on the published surface.

WHY THIS IS NEEDED. `params` is interpolation data: the handler renders
`errors.NOT_FOUND` with whatever the call site passed, and a caller-supplied
English word lands inside a translated sentence unchanged. That is how
"proxy provider nicht gefunden." was produced -- a German template with an
English subject. A localized client cannot repair it, because by the time the
text reaches the client the two languages are already one string.

The fix is the one the validation path already uses: send the machine name and
let the client resolve its own label. `invalid_params[].field` carries
`dept_id`, never "Department", and the form maps it through
`forms.<entity>.<field>`. A public NOT_FOUND now carries `proxy_provider`, and
the client maps it through `common.resource.<token>`.

WHAT THIS GUARDS. Two things a review would not reliably catch:
  1. a NEW public producer passing prose, which renders correctly in English and
     is wrong only in German -- invisible unless someone reads the German;
  2. a token with no label, which renders the raw token to every reader.

SCOPE IS DELIBERATE. Only the 8 published producers are held to the vocabulary.
The 50 internal ones still pass free English words; they are read by the
dashboard, which ships with them. Pinning them here would convert a later
cleanup into a test rewrite, and pinning them loosely would guard nothing. The
public set is pinned by (file, function) rather than by line so the guard
survives ordinary edits above it.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

from errors.catalog import ERROR_CATALOG, ErrorCode

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_API_DIR = _REPO_ROOT / "api"

# The published NOT_FOUND producers, by the route function that owns them.
# Sourced from the audit, not from filenames: every entry was confirmed to sit
# on an operation with include_in_schema=True.
_PUBLIC_PRODUCERS: dict[tuple[str, str], str] = {
    ("api/v1/endpoints/ai.py", "get_request"): "request",
    ("api/v1/endpoints/keys.py", "create_key"): "application|department",
    ("api/v1/endpoints/proxy_interactions.py", "get_proxy_interaction"): "interaction",
    ("api/v1/endpoints/proxy_settings.py", "get_proxy_settings"): "proxy_provider",
    ("api/v1/endpoints/proxy_settings.py", "delete_proxy_settings"): "proxy_provider",
}

# The vocabulary itself. Adding a token here is a public-contract change and
# needs a label in every locale -- which the label test below enforces.
_TOKENS = frozenset({"request", "application", "department", "interaction", "proxy_provider"})

_LABEL_NAMESPACE = "resource"


def _public_resource_values() -> list[tuple[str, str, int, str]]:
    """(file, function, line, resource) for every literal in a public producer."""
    found: list[tuple[str, str, int, str]] = []
    for (rel, fname) in _PUBLIC_PRODUCERS:
        tree = ast.parse((_REPO_ROOT / rel).read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name != fname:
                continue
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if name != "NotFoundError":
                    continue
                value = None
                if node.args and isinstance(node.args[0], ast.Constant):
                    value = node.args[0].value
                for kw in node.keywords:
                    if kw.arg == "resource" and isinstance(kw.value, ast.Constant):
                        value = kw.value.value
                if isinstance(value, str):
                    found.append((rel, fname, node.lineno, value))
    return found


def _locales() -> list[str]:
    meta = json.loads((_REPO_ROOT / "locales" / "_meta.json").read_text(encoding="utf-8"))
    return sorted(meta["locales"])


def _labels(locale: str) -> dict[str, str]:
    common = json.loads(
        (_REPO_ROOT / "locales" / locale / "common.json").read_text(encoding="utf-8")
    )
    return common.get(_LABEL_NAMESPACE, {})


def test_the_public_producers_are_all_found():
    """The pin is by (file, function), so a rename would silently empty this
    guard rather than fail it. Assert the count first."""
    found = _public_resource_values()
    assert len(found) == 8, (
        f"expected 8 published NOT_FOUND producers, found {len(found)}: {found}. "
        "A producer was added, removed or renamed -- update _PUBLIC_PRODUCERS "
        "deliberately rather than letting the vocabulary go unchecked."
    )


@pytest.mark.parametrize("rel,fname,line,value", _public_resource_values())
def test_every_public_resource_is_a_known_token(rel, fname, line, value):
    assert value in _TOKENS, (
        f"{rel}:{line} passes {value!r}, which is not in the public resource "
        f"vocabulary {sorted(_TOKENS)}. A public NOT_FOUND carries a machine "
        "token; the human label belongs in common.resource."
    )


@pytest.mark.parametrize("rel,fname,line,value", _public_resource_values())
def test_no_public_resource_is_prose(rel, fname, line, value):
    """The shape rule, independent of the vocabulary list.

    A token is lowercase and unspaced. This catches a plausible new value
    ("api key", "Proxy Provider") even if someone also adds it to _TOKENS.
    """
    assert value == value.lower(), f"{rel}:{line} resource {value!r} is not lowercase"
    assert " " not in value, f"{rel}:{line} resource {value!r} contains a space"


@pytest.mark.parametrize("locale", _locales())
def test_every_token_has_a_label_in_every_locale(locale):
    missing = sorted(t for t in _TOKENS if t not in _labels(locale))
    assert not missing, (
        f"locale {locale!r} has no common.{_LABEL_NAMESPACE} label for {missing}. "
        "A token with no label renders as the raw token to that reader."
    )


@pytest.mark.parametrize("locale", _locales())
def test_no_orphan_resource_labels(locale):
    """A label for a token nothing sends is dead text a translator maintains."""
    extra = sorted(set(_labels(locale)) - _TOKENS)
    assert not extra, f"locale {locale!r} carries unused resource labels: {extra}"


def test_the_three_interaction_branches_share_one_token():
    """The security property, at the source.

    The detail route answers "no such interaction", "another tenant's" and
    "another key's" identically on purpose. A token that differed by branch
    would reintroduce the distinction the identical arguments exist to remove --
    and it would do so in `params`, which is serialized.
    """
    values = [
        v for rel, fname, _, v in _public_resource_values()
        if fname == "get_proxy_interaction"
    ]
    assert len(values) == 3, f"expected 3 branches, found {len(values)}"
    assert set(values) == {"interaction"}, f"branches diverged: {values}"


def test_the_german_labels_are_actually_translated():
    """English tokens in a German catalog would defeat the whole change: the
    message would render exactly as it did before, and every other test here
    would still pass."""
    de = _labels("de")
    en = _labels("en")
    shared = sorted(t for t in _TOKENS if de.get(t) == en.get(t))
    assert not shared, (
        f"German resource labels are identical to English for {shared} -- the "
        "token is reaching the reader untranslated."
    )


def test_not_found_remains_a_404_in_the_catalog():
    """The vocabulary change is presentation only. The transport is not part of
    it, and a status drift here would be a silent public-contract change."""
    assert ERROR_CATALOG[ErrorCode.NOT_FOUND].status_code == 404
    assert ERROR_CATALOG[ErrorCode.NOT_FOUND].localization_key == "errors.NOT_FOUND"


def test_the_resource_labels_are_not_error_catalog_keys():
    """common.resource.* is UI text, not error metadata. If it ever became a
    catalog key the backend would start resolving labels server-side, which is
    the behaviour this design exists to avoid."""
    generated = json.loads(
        (_REPO_ROOT / "errors" / "errors_en.generated.json").read_text(encoding="utf-8")
    )
    flat = json.dumps(generated)
    for token in _TOKENS:
        assert f"common.{_LABEL_NAMESPACE}.{token}" not in flat, (
            f"{token} leaked into the backend error map; the server must send "
            "the token and resolve nothing."
        )
