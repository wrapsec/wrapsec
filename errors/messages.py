# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Backend English message resolver.

Loads the committed, generated English map (errors/errors_en.generated.json) and
renders the convenience `message` the API returns and logs. The backend never
reads the frontend locales at runtime -- only this generated artifact -- so the
API stands alone. The authoritative localized text (plurals, gender, German
grammar) is resolved on the frontend by next-intl from the same locale source;
the backend only ever renders the SIMPLE-ARGUMENT ICU subset ({name}), so it
needs no ICU dependency.

The map is static generated data (not settings), so it is loaded once and
cached; regeneration happens at build time, not runtime.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_GENERATED_FILE = Path(__file__).resolve().parent / "errors_en.generated.json"

# {identifier} -- ICU simple argument. Backend error strings use only this
# subset (no plural/select/number), so a bounded token substitution is exact.
_ARG = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

_messages: dict[str, str] | None = None


def _load() -> dict[str, str]:
    global _messages
    if _messages is None:
        with _GENERATED_FILE.open(encoding="utf-8") as fh:
            data = json.load(fh)
        # Skip the self-labeling header; keep only the message map.
        _messages = dict(data.get("messages", {}))
    return _messages


def render(template: str, params: dict[str, Any] | None) -> str:
    """
    Substitute {name} tokens from params. A token with no matching param is left
    verbatim (never raises, never leaks an unrelated value). Not str.format --
    that would expose attribute/index access on the format string.
    """
    if not params:
        return template
    return _ARG.sub(
        lambda m: str(params[m.group(1)]) if m.group(1) in params else m.group(0),
        template,
    )


def get_message(key: str, params: dict[str, Any] | None = None) -> str | None:
    """Rendered English for a localization key, or None if the key is unknown."""
    template = _load().get(key)
    if template is None:
        return None
    return render(template, params)
