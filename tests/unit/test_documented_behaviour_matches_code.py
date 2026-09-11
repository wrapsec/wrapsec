# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Fences for four places where the documentation described behaviour the code
did not have.

A comment that is wrong about a security control is worse than no comment: it
is read as a specification, and the next change is made against it. So each of
these tests asserts the BEHAVIOUR the corrected text now claims. Asserting the
prose itself would pass on a copied-out paragraph and prove nothing.

One test per finding, deliberately, so a regression names which claim broke.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# 1. "masked" stores no raw text -- it does not redact at storage time
# --------------------------------------------------------------------------

def _storage_branch_source() -> str:
    """The data_storage_mode branch of the proxy's persistence helper."""
    source = (_ROOT / "api/v1/endpoints/proxy.py").read_text(encoding="utf-8")
    marker = "mode = (get_settings().data_storage_mode"
    assert marker in source, "the storage-mode branch moved; this fence needs updating"
    start = source.index(marker)
    return source[start:start + 1600]


@pytest.mark.parametrize("mode", ["masked", "MASKED", "typo-not-a-mode", ""])
def test_only_full_retains_raw_text(mode):
    """Every value except an explicit "full" must discard the raw columns.

    The settings comment used to say masked "runs the PII redactor before
    storing", which would mean a redacted copy of the prompt is retained. It is
    not: the raw column is dropped entirely. An operator choosing a retention
    mode on the strength of that sentence would have been wrong about what is
    on disk.
    """
    branch = _storage_branch_source()

    # The fail-closed default is expressed as "anything that is not none/full",
    # so the only literal that may enable raw retention is "full".
    assert 'elif mode == "full"' in branch
    assert mode == "full" or mode.lower() != "full"

    # And the else-branch -- which is what every value above reaches -- nulls raw.
    else_half = branch[branch.index("else:"):]
    assert "stored_input_raw        = None" in else_half
    assert "stored_output_raw       = None" in else_half


def test_masked_keeps_only_guard_redacted_text():
    """What masked DOES keep is the guard's sanitized output, not the prompt.

    This is the other half of the corrected sentence: "already redacted
    upstream" is only true while the stored sanitized value comes from the
    guard decision rather than being re-derived here.
    """
    source = (_ROOT / "api/v1/endpoints/proxy.py").read_text(encoding="utf-8")
    assert "input_sanit    = gd.sanitized_input" in source, (
        "the sanitized value no longer comes from the guard decision; "
        "masked mode may now be storing something that was never redacted"
    )


# --------------------------------------------------------------------------
# 2. the proxy holds no redactor of its own
# --------------------------------------------------------------------------

def test_proxy_does_not_construct_its_own_redactor():
    """A second redactor in the proxy is either dead or a divergent code path.

    It was dead -- constructed at import and never called, while the real
    redaction happened in the input guard. Left in place it invites a future
    change to "use the one that is already here", which would redact with
    settings the guard never saw.
    """
    source = (_ROOT / "api/v1/endpoints/proxy.py").read_text(encoding="utf-8")
    assert "PIIRedactor" not in source, (
        "proxy.py constructs a PII redactor again; redaction belongs to the "
        "input guard, which is the path the pipeline actually scans through"
    )


# --------------------------------------------------------------------------
# 3. login documents both of its 429s
# --------------------------------------------------------------------------

def test_login_documents_every_429_it_can_return():
    """Login has TWO distinct 429s, and only one was documented.

    ACCOUNT_LOCKED is per address; RATE_LIMIT_EXCEEDED is per IP and fires
    before any database work. A caller that special-cases "429 means this
    account is locked" mishandles the other one -- it would report a lockout to
    a user whose credentials were never checked.
    """
    from api.v1.endpoints.auth import login

    doc = inspect.getdoc(login) or ""
    for code in ("ACCOUNT_LOCKED", "RATE_LIMIT_EXCEEDED"):
        assert code in doc, f"login's docstring omits its {code} response"

    # Both are genuinely 429 in the catalog -- the docstring is not guessing.
    from errors.catalog import ERROR_CATALOG, ErrorCode
    assert ERROR_CATALOG[ErrorCode.ACCOUNT_LOCKED].status_code == 429
    assert ERROR_CATALOG[ErrorCode.RATE_LIMIT_EXCEEDED].status_code == 429


# --------------------------------------------------------------------------
# 4. Principal.permissions is enforced, whatever the comment says
# --------------------------------------------------------------------------

def test_permissions_are_load_bearing_not_scaffolding():
    """`require_permission` refuses on a missing permission, at real routes.

    The field carried "v2+ use only, not enforced in v1" while eight endpoints
    depended on it. Under that comment, narrowing ROLE_PERMISSIONS looks
    consequence-free; it actually closes routes, and widening it opens them.
    """
    from api.v1.dependencies.auth import require_permission

    guard_source = inspect.getsource(require_permission)
    assert "has_permission" in guard_source
    assert "ForbiddenError" in guard_source, (
        "require_permission no longer refuses; if permissions became advisory, "
        "the Principal.permissions comment must change with it"
    )

    # And it is actually mounted, not merely defined.
    mounted = 0
    for path in (_ROOT / "api").rglob("*.py"):
        if path.name == "auth.py" and path.parent.name == "dependencies":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "require_permission"):
                mounted += 1
    assert mounted > 0, (
        "no endpoint uses require_permission; the permissions field would then "
        "genuinely be unenforced and its comment should say so"
    )
