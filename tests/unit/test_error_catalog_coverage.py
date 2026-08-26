# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The error catalog is the only source of error metadata, and nothing may name a
code it does not define.

WHY THIS IS NEEDED. `WrapSecError` accepts `code=` as a plain string for
backward compatibility, and `_coerce_code` falls back to `INTERNAL_ERROR` when
the string is not a member of `ErrorCode`. That fallback is deliberate -- it
keeps a bad call site from crashing a request -- but it is silent. A site that
names a code which does not exist still returns a well-formed envelope, so
nothing about the response looks wrong: the status, the severity and the
localization key all come from `INTERNAL_ERROR` instead of the intended code,
and an SDK or a SIEM rule branching on the code sees the wrong one. Nothing in
the test suite or in review catches it, because the output is valid.

WHAT THIS IS NOT. It is not a search for strings that look like error text.
Prose is not checked, and a message literal is not a finding. The check reads
one specific argument position -- `code=` on an error construction -- which is
the position whose value must be a catalog member for the envelope to be
correct. That is what makes it a structural invariant rather than a lint.

RATCHET, NOT A CLEAN SWEEP. `_KNOWN_INVALID_CODES` records the violations that
existed when this guard was written. Each entry is a real defect awaiting its
own change, not an approved pattern: the guard's value is that a NEW one fails
immediately, and that removing an entry after fixing it is a one-line diff. Do
not add to this dict to make a new call site pass.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from errors.catalog import ERROR_CATALOG, ErrorCode
from errors.messages import get_message

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Directories with no bearing on what the API emits.
_SKIP = (".venv", "node_modules", "/tests/", "/migrations/", "/dashboard/", "/sdk/")

# Constructions whose `code=` argument selects the catalog entry.
_ERROR_BUILDERS = {"error_response", "build_error_envelope"}

# Recorded violations. See RATCHET above -- an entry is a defect awaiting its own
# change, never an approved pattern.
#
# EMPTY, and that is the point: the one entry this guard was written with
# (settings.py naming SYSTEM_ERROR, an audit primary_reason rather than an
# ErrorCode) has since been corrected to INTERNAL_ERROR -- the code it was
# already being coerced to, so the wire response never changed. The guard now
# holds the whole repository to the rule with no exceptions.
_KNOWN_INVALID_CODES: dict[tuple[str, str], str] = {}


def _source_files():
    for path in _REPO_ROOT.rglob("*.py"):
        rel = path.relative_to(_REPO_ROOT).as_posix()
        if any(part in f"/{rel}" for part in _SKIP):
            continue
        yield rel, path


def _literal_code_arguments() -> list[tuple[str, int, str, str]]:
    """Every `code="LITERAL"` passed to an error construction.

    Only a string constant is reported. A `code=ErrorCode.X` argument is already
    proven by the type, and a computed expression cannot be resolved statically
    -- neither is a finding, and reporting them would make this noisy enough to
    be ignored.
    """
    found: list[tuple[str, int, str, str]] = []
    for rel, path in _source_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", "")
            if not (name.endswith("Error") or name in _ERROR_BUILDERS):
                continue
            for kw in node.keywords:
                if (
                    kw.arg == "code"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    found.append((rel, node.lineno, name, kw.value.value))
    return found


# ── the catalog itself ───────────────────────────────────────────────────────

def test_every_error_code_has_a_catalog_entry():
    """An enum member with no entry raises a KeyError inside the error handler --
    that is, the failure surfaces only while already handling a failure."""
    missing = sorted(c.value for c in ErrorCode if c not in ERROR_CATALOG)
    assert not missing, f"ErrorCode members with no catalog entry: {missing}"


def test_no_catalog_entry_names_a_code_that_does_not_exist():
    """The other direction, so the two never drift apart silently."""
    orphans = sorted(str(c) for c in ERROR_CATALOG if c not in set(ErrorCode))
    assert not orphans, f"catalog entries with no ErrorCode member: {orphans}"


@pytest.mark.parametrize("code", sorted(ERROR_CATALOG, key=lambda c: c.value))
def test_every_catalog_key_resolves_to_a_message(code):
    """The catalog holds no text -- it holds a key. A key that resolves to
    nothing produces an envelope whose `message` falls back to the raw code,
    which is what a caller then shows a user."""
    meta = ERROR_CATALOG[code]
    assert meta.localization_key.startswith("errors."), (
        f"{code.value} localization key does not carry the domain namespace: "
        f"{meta.localization_key}"
    )
    assert get_message(meta.localization_key, {}), (
        f"{code.value} resolves to no message via {meta.localization_key}"
    )


# ── the invariant ────────────────────────────────────────────────────────────

def test_no_error_site_names_a_code_outside_the_catalog():
    """The guard. A `code=` string that is not an ErrorCode is silently coerced
    to INTERNAL_ERROR, so the response looks correct while carrying the wrong
    code, status and severity."""
    valid = {c.value for c in ErrorCode}

    offenders = [
        (rel, line, builder, code)
        for rel, line, builder, code in _literal_code_arguments()
        if code not in valid and (rel, code) not in _KNOWN_INVALID_CODES
    ]

    assert not offenders, (
        "error sites naming a code the catalog does not define (each is "
        "silently coerced to INTERNAL_ERROR):\n  "
        + "\n  ".join(f"{r}:{ln} {b}(code={c!r})" for r, ln, b, c in offenders)
        + "\nAdd the code to ErrorCode with a catalog entry and a locales string, "
          "or name the code the site actually means."
    )


def test_the_recorded_violations_are_still_real():
    """A ratchet entry that no longer describes anything is a false statement
    about the codebase, and it silently re-permits the pattern if the same file
    reintroduces it later."""
    valid   = {c.value for c in ErrorCode}
    present = {(rel, code) for rel, _, _, code in _literal_code_arguments()}

    for entry, reason in _KNOWN_INVALID_CODES.items():
        rel, code = entry
        assert entry in present, (
            f"{rel} no longer names {code!r}. If it was fixed, delete this entry "
            f"from _KNOWN_INVALID_CODES. Recorded reason: {reason}"
        )
        assert code not in valid, (
            f"{code!r} is now a real ErrorCode, so this is no longer a violation "
            f"-- delete the entry for {rel}"
        )


# ── redundant public message overrides ───────────────────────────────────────

def _literal_message_overrides() -> list[tuple[str, int, str, str]]:
    """Every `error_response(ErrorCode.X, ..., message="literal")` in source.

    Only a literal is resolvable statically. A computed message (an f-string, a
    variable) is skipped rather than guessed at -- it cannot be compared to the
    catalog without running it, and reporting it would make this guard noise.
    """
    found: list[tuple[str, int, str, str]] = []
    for rel, path in _source_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", "")
            if name not in {"error_response", "_catalog_error_response"}:
                continue
            message = next(
                (k.value for k in node.keywords
                 if k.arg == "message" and isinstance(k.value, ast.Constant)
                 and isinstance(k.value.value, str)),
                None,
            )
            if message is None:
                continue
            # First positional arg is the ErrorCode; resolve `ErrorCode.X`.
            code = None
            if node.args and isinstance(node.args[0], ast.Attribute):
                code = node.args[0].attr
            if code:
                found.append((rel, node.lineno, code, message.value))
    return found


def test_no_canonical_error_repeats_its_own_catalog_message():
    """A `message=` that duplicates the catalog string is a second source of
    truth for one piece of text.

    Both render correctly today, which is exactly why the drift is silent: change
    the locale string and the override keeps serving the old English, with
    nothing failing. The override is not banned -- one that genuinely adds
    context is a deliberate choice, and this ignores it. Only EXACT duplication
    is reported.

    A computed message is out of scope here by construction; see
    `_literal_message_overrides`.
    """
    redundant = []
    for rel, line, code, message in _literal_message_overrides():
        member = getattr(ErrorCode, code, None)
        if member is None or member not in ERROR_CATALOG:
            continue
        catalog_text = get_message(ERROR_CATALOG[member].localization_key, {})
        if message == catalog_text:
            redundant.append(f"{rel}:{line} {code} repeats the catalog string {message!r}")

    assert not redundant, (
        "canonical errors passing a message identical to their catalog text:\n  "
        + "\n  ".join(redundant)
        + "\nDrop the `message=` and let the catalog own it."
    )
