# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Notification rendering (v1.8.3).

Turns a (notification_type, locale, context) triple into a fully localized,
ready-to-send message: a subject from the canonical locale catalog and HTML +
plain-text bodies from per-locale template files. Rendering happens once, at
enqueue time, so the outbox stores final content and the delivery worker stays
template- and locale-agnostic.

Localization sources (single architecture, no second i18n system):

  * Subjects come from the canonical `locales/<loc>/notifications.json`
    namespace -- the SAME catalog the dashboard consumes -- read directly here
    (the backend error map in errors/ is English-only and errors-only). The
    lockstep/parity guards in tests validate these keys.
  * Bodies come from `services/email/templates/<loc>/<type>.{html,txt}`, which
    hold the localized prose. Rich HTML does not belong in the flat ICU-subset
    catalog, so bodies are per-locale template files by design.

Both fall back to English (the catalog floor) when a locale is missing a key or
a template, matching the rest of the platform's resolution policy.

Security: values interpolated into the HTML body are HTML-escaped, so a value
that happens to contain markup (for example an email address) cannot inject
markup into the message. Templates use inline styles only (no `<style>` blocks)
so the `{token}` placeholder scheme never collides with CSS braces. Substitution
is strict: a template placeholder with no matching context value raises, which
surfaces a template/caller mismatch in tests rather than shipping a literal
`{token}` to a user.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from domain.enums import NotificationType, is_implemented
from services.localization import FLOOR, canonical_locale, supported_locales

_REPO_ROOT     = Path(__file__).resolve().parent.parent.parent
_LOCALES_DIR   = _REPO_ROOT / "locales"
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# {identifier} placeholder -- the same simple-argument scheme used across the
# backend (errors/messages.py). No attribute/index access, so it is safe on
# untrusted values once they are escaped for the target format.
_TOKEN = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

# Context keys each IMPLEMENTED notification type's templates and subject
# require. The caller (the trigger site) must supply exactly these; extra keys
# are ignored. Only implemented types appear here -- a reserved type has no
# contract and render() rejects it. Guards keep this in lockstep with
# IMPLEMENTED_NOTIFICATIONS.
REQUIRED_CONTEXT: dict[NotificationType, tuple[str, ...]] = {
    NotificationType.PASSWORD_CHANGED:        ("display_name", "event_time"),
    NotificationType.PASSWORD_RESET_BY_ADMIN: ("display_name", "event_time"),
    NotificationType.ACCOUNT_LOCKED:          ("display_name", "event_time", "lockout_minutes"),
}


@dataclass(frozen=True)
class RenderedNotification:
    subject:   str
    text_body: str
    html_body: str


class TemplateError(Exception):
    """A notification could not be rendered (missing template or context)."""


def _resolve_locale(locale: str | None) -> str:
    """Canonicalize to a supported locale, or fall back to the English floor."""
    canonical = canonical_locale(locale, supported_locales())
    return canonical or FLOOR


@lru_cache
def _subjects_for_locale(locale: str) -> dict[str, str]:
    """
    Flattened `notifications.*` subject map for one locale, read straight from
    the canonical catalog. Cached: the catalog is static generated-source data.
    Returns {} if the locale has no notifications file.
    """
    path = _LOCALES_DIR / locale / "notifications.json"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    flat: dict[str, str] = {}
    _flatten(data, "notifications", flat)
    return flat


def _flatten(node: Any, prefix: str, out: dict[str, str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _flatten(value, f"{prefix}.{key}" if prefix else key, out)
    elif isinstance(node, str):
        out[prefix] = node


@lru_cache
def _template(locale: str, notification_type: str, suffix: str) -> str | None:
    """Raw template text for locale+type+suffix (html|txt), or None if absent."""
    path = _TEMPLATES_DIR / locale / f"{notification_type}.{suffix}"
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def _substitute(template: str, params: dict[str, str], *, escape: bool) -> str:
    """
    Replace {token} with params[token]. Strict: an unknown token raises
    TemplateError. Values are HTML-escaped when `escape` is True (HTML body),
    left verbatim otherwise (text body / subject).
    """
    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in params:
            raise TemplateError(f"template placeholder '{{{name}}}' has no context value")
        value = str(params[name])
        return html.escape(value) if escape else value

    return _TOKEN.sub(repl, template)


def render(
    notification_type: NotificationType,
    locale: str | None,
    context: dict[str, Any],
) -> RenderedNotification:
    """
    Render a notification to subject + text + HTML for the given locale.

    Raises TemplateError if a required context key is missing or a template for
    the type is absent even after English fallback (a packaging/programming
    error). Callers that must not fail their business transaction wrap this and
    degrade gracefully.
    """
    if not is_implemented(notification_type):
        raise TemplateError(
            f"notification type '{notification_type.value}' is reserved "
            f"(registered but not implemented); no template or context contract"
        )
    required = REQUIRED_CONTEXT[notification_type]
    missing = [k for k in required if k not in context]
    if missing:
        raise TemplateError(
            f"missing context for '{notification_type.value}': {sorted(missing)}"
        )

    loc      = _resolve_locale(locale)
    type_str = notification_type.value

    # Subject: locale catalog, then English floor.
    subject_key = f"notifications.{type_str}.subject"
    subject_tpl = _subjects_for_locale(loc).get(subject_key) or _subjects_for_locale(FLOOR).get(subject_key)
    if subject_tpl is None:
        raise TemplateError(f"no subject for '{subject_key}' in catalog")

    # Bodies: locale template, then English floor.
    text_tpl = _template(loc, type_str, "txt")  or _template(FLOOR, type_str, "txt")
    html_tpl = _template(loc, type_str, "html") or _template(FLOOR, type_str, "html")
    if text_tpl is None or html_tpl is None:
        raise TemplateError(f"missing body template(s) for '{type_str}'")

    str_context = {k: str(v) for k, v in context.items()}
    return RenderedNotification(
        subject   = _substitute(subject_tpl, str_context, escape=False).strip(),
        text_body = _substitute(text_tpl, str_context, escape=False),
        html_body = _substitute(html_tpl, str_context, escape=True),
    )
