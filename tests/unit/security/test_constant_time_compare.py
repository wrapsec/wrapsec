# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The comparison must stay constant time while tolerating any input.

The point of this helper is that fixing the crash MUST NOT be done by lowering
the comparison to `==`, or by short-circuiting on length, or by normalising the
values first. Those all make the check cheaper to attack than the thing it
protects.

`test_the_comparison_is_not_lowered_to_equality` reads the source for that,
because behaviour alone cannot distinguish a constant-time comparison from a
fast one -- both return the same answers.
"""

from __future__ import annotations

import pytest

from security.compare import constant_time_equals


@pytest.mark.parametrize("value", ["café", "ключ", "🔑", "plain-ascii"])
def test_a_non_ascii_value_compares_instead_of_raising(value):
    assert constant_time_equals(value, "the-expected-secret") is False
    assert constant_time_equals(value, value) is True


@pytest.mark.parametrize("presented,expected", [
    ("secret", "secret"),
    ("café",   "café"),
    (b"bytes", b"bytes"),
    ("mixed",  b"mixed"),
])
def test_equal_values_match(presented, expected):
    assert constant_time_equals(presented, expected) is True


@pytest.mark.parametrize("presented,expected", [
    ("secret", "secrez"),
    ("secret", "secret-longer"),
    ("café",   "cafe"),
])
def test_different_values_do_not_match(presented, expected):
    assert constant_time_equals(presented, expected) is False


@pytest.mark.parametrize("presented,expected", [
    (None, "secret"), ("secret", None), ("", "secret"), ("secret", ""), (None, None),
])
def test_a_missing_secret_is_never_a_match(presented, expected):
    """An empty expected value must not authenticate an empty credential."""
    assert constant_time_equals(presented, expected) is False


def test_a_value_that_is_not_valid_utf8_still_compares():
    """A header can carry bytes the framework surfaces as lone surrogates.
    Encoding must not raise a second, different exception."""
    lone_surrogate = "\udce9"

    assert constant_time_equals(lone_surrogate, "secret") is False
    assert constant_time_equals(lone_surrogate, lone_surrogate) is True


def test_the_comparison_is_not_lowered_to_equality():
    """Behaviour cannot tell a constant-time comparison from a fast one.

    So this reads the implementation: it must delegate to `compare_digest` and
    must not contain a plain equality on the credential values. Fixing the crash
    by comparing with `==` would answer every other test here identically while
    reintroducing a timing oracle on the admin credential.
    """
    import inspect

    import security.compare as module

    source = inspect.getsource(module.constant_time_equals)

    assert "compare_digest" in source, (
        "the helper no longer delegates to compare_digest"
    )
    assert "==" not in source, (
        "the helper contains a plain equality comparison; a credential check "
        "must not short-circuit on the first differing byte"
    )
