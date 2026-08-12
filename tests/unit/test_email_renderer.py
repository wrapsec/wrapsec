# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for notification rendering (v1.8.3, Phase E).

Covers subject/body rendering, locale resolution + English fallback, HTML
escaping of interpolated values, strict context validation, and completeness
guards so no notification type ships without a template or a subject in a
supported locale.
"""

from __future__ import annotations

import pytest

from domain.enums import (
    IMPLEMENTED_NOTIFICATIONS,
    NOTIFICATION_CATEGORY,
    NotificationType,
    is_implemented,
)
from services.email import renderer as R
from services.email.renderer import (
    REQUIRED_CONTEXT,
    TemplateError,
    _subjects_for_locale,
    _template,
    render,
)
from services.localization import supported_locales


def _ctx(notification_type: NotificationType) -> dict[str, str]:
    return {k: f"val_{k}" for k in REQUIRED_CONTEXT[notification_type]}


# -- basic rendering -------------------------------------------------
def test_render_returns_subject_text_and_html_for_every_implemented_type():
    for nt in IMPLEMENTED_NOTIFICATIONS:
        r = render(nt, "en", _ctx(nt))
        assert r.subject and "WrapSec" in r.subject
        assert r.text_body.strip()
        assert r.html_body.strip().startswith("<")


def test_render_interpolates_context_into_bodies():
    r = render(
        NotificationType.ACCOUNT_LOCKED,
        "en",
        {"display_name": "sam@example.com", "event_time": "2026-08-12T10:00:00Z", "lockout_minutes": "15"},
    )
    assert "sam@example.com" in r.text_body
    assert "2026-08-12T10:00:00Z" in r.text_body
    assert "15 minutes" in r.text_body


# -- locale resolution + fallback -----------------------------------
def test_german_renders_german_subject():
    r = render(NotificationType.PASSWORD_CHANGED, "de", {"display_name": "x", "event_time": "t"})
    assert "geändert" in r.subject
    assert "Hallo" in r.text_body


@pytest.mark.parametrize("loc", [None, "zz", "fr"])
def test_unsupported_or_missing_locale_falls_back_to_english(loc):
    r = render(NotificationType.PASSWORD_CHANGED, loc, {"display_name": "x", "event_time": "t"})
    assert r.subject == "Your WrapSec password was changed"


# -- HTML escaping ---------------------------------------------------
def test_html_body_escapes_interpolated_values():
    payload = "<b>evil</b>@x.com"
    r = render(NotificationType.PASSWORD_CHANGED, "en", {"display_name": payload, "event_time": "t"})
    assert "&lt;b&gt;evil&lt;/b&gt;" in r.html_body
    assert payload not in r.html_body


def test_text_body_does_not_escape_values():
    payload = "<b>evil</b>@x.com"
    r = render(NotificationType.PASSWORD_CHANGED, "en", {"display_name": payload, "event_time": "t"})
    assert payload in r.text_body


# -- strict context validation --------------------------------------
def test_missing_context_key_raises():
    with pytest.raises(TemplateError):
        render(NotificationType.ACCOUNT_LOCKED, "en", {"display_name": "x", "event_time": "t"})  # no lockout_minutes


# -- taxonomy invariants (Registered != Implemented != Sendable) ----
def test_every_registered_type_has_a_category():
    assert set(NotificationType) == set(NOTIFICATION_CATEGORY)


def test_implemented_is_a_subset_of_registered():
    assert IMPLEMENTED_NOTIFICATIONS <= set(NotificationType)
    assert all(is_implemented(nt) for nt in IMPLEMENTED_NOTIFICATIONS)


def test_reserved_types_are_registered_but_not_implemented():
    reserved = set(NotificationType) - IMPLEMENTED_NOTIFICATIONS
    assert reserved, "expected some reserved (future) types"
    for nt in reserved:
        assert not is_implemented(nt)


def test_reserved_type_render_is_rejected():
    reserved = next(iter(set(NotificationType) - IMPLEMENTED_NOTIFICATIONS))
    with pytest.raises(TemplateError):
        render(reserved, "en", {"display_name": "x", "event_time": "t"})


# -- completeness guards (implemented types only) -------------------
def test_context_contract_covers_exactly_the_implemented_types():
    assert set(REQUIRED_CONTEXT) == set(IMPLEMENTED_NOTIFICATIONS)


def test_every_supported_locale_has_all_templates_and_subjects():
    """No fallback allowed for a shipped locale: every supported locale must
    carry its own HTML + text template and subject for every IMPLEMENTED
    notification type, so we never ship a half-translated security email."""
    for loc in supported_locales():
        subjects = _subjects_for_locale(loc)
        for nt in IMPLEMENTED_NOTIFICATIONS:
            key = f"notifications.{nt.value}.subject"
            assert key in subjects, f"locale {loc} missing subject {key}"
            assert _template(loc, nt.value, "html") is not None, f"{loc} missing {nt.value}.html"
            assert _template(loc, nt.value, "txt") is not None, f"{loc} missing {nt.value}.txt"


def test_templates_reference_only_known_context_tokens():
    """Every {token} in a template must be a declared context key, so strict
    substitution can never raise at send time for a well-formed call."""
    for loc in supported_locales():
        for nt in IMPLEMENTED_NOTIFICATIONS:
            allowed = set(REQUIRED_CONTEXT[nt])
            for suffix in ("html", "txt"):
                body = _template(loc, nt.value, suffix)
                tokens = set(R._TOKEN.findall(body))
                extra = tokens - allowed
                assert not extra, f"{loc}/{nt.value}.{suffix} has undeclared tokens: {extra}"
