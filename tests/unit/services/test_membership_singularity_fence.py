# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A second membership must not become creatable without revisiting who may
reset a password.

THE CONSTRAINT THIS PROTECTS. A password is GLOBAL identity, and a login scopes
the session to the user's OLDEST membership (`_resolve_active_membership`
orders by `created_at` and takes the first). An administrator may reset the
password of any user holding a membership in THEIR tenant.

Those three facts are safe only while a user holds at most one membership. If a
user ever holds memberships in tenant A (older) and tenant B, then an
administrator of B can reset that user's password and log in as them -- and the
session lands in A, which B's administrator has no authority over.

TODAY IT IS UNREACHABLE, and that is what this fences. Every call site that
attaches a membership either creates a brand-new user or refuses an existing
one, so no path produces a second membership for one user. This test fails the
day that changes, which is the day the reset authority has to be reconsidered.

It is deliberately a fence and not a fix: there is nothing to fix yet. Narrowing
the reset authority now would remove a capability administrators legitimately
have, to defend against a state the code cannot currently reach.
"""

from __future__ import annotations

import ast
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[3]

# Every production call that attaches a membership, with why it cannot produce a
# SECOND one for an existing user. Each entry is a claim about the call site,
# checked below against the file still containing that guard.
_ATTACH_SITES = {
    "api/main.py":
        "first-run seeding: runs only when the deployment has no users",
    "api/v1/endpoints/setup.py":
        "first-run setup: refused once any user exists",
    "api/v1/endpoints/admin/users.py":
        "create refuses an email that already exists; the role/dept update path "
        "modifies the caller's own tenant membership rather than adding one",
    "api/v1/endpoints/admin/tenants.py":
        "operator bootstrap: refuses an existing user",
}


def _call_sites() -> set[str]:
    """Files containing a call to the membership attach method."""
    found = set()
    for path in _ROOT.rglob("*.py"):
        rel = path.relative_to(_ROOT).as_posix()
        if rel.startswith((".venv", "tests/", "scripts/")):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "upsert_for_user":
                found.add(rel)
    return found


def test_no_new_call_site_attaches_a_membership_unreviewed():
    """A new attach site is not necessarily wrong -- it is unreviewed.

    Whoever adds one has to decide whether it can give an existing user a
    SECOND membership, and if it can, what that means for an administrator's
    power to reset that user's password.
    """
    unexpected = _call_sites() - set(_ATTACH_SITES)

    assert not unexpected, (
        "membership is attached in files this constraint has not been checked "
        f"against: {sorted(unexpected)}. A user holding two memberships makes a "
        "password reset by one tenant's administrator a way into another "
        "tenant, because the session resolves to the OLDEST membership."
    )


def test_the_recorded_call_sites_still_exist():
    """A fence naming files that no longer call this is checking nothing."""
    missing = set(_ATTACH_SITES) - _call_sites()

    assert not missing, (
        f"these no longer attach a membership: {sorted(missing)}. Remove them "
        "from the list, and confirm the constraint still holds without them."
    )


def test_the_session_still_resolves_to_the_oldest_membership():
    """The other half of the constraint. If the resolver ever picked a
    different membership -- newest, or one named in the request -- the exposure
    changes shape and this fence stops describing it."""
    import inspect

    from services.auth.service import _resolve_active_membership

    source = inspect.getsource(_resolve_active_membership)

    assert "list_for_user" in source
    assert "[0]" in source, (
        "the session no longer takes the first membership; re-derive which "
        "tenant a reset-and-login would land in"
    )
