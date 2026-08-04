# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Input validation - length limits, token estimate, charset normalisation.

Called by client before sending to API - never duplicated in CLI commands.

Spec reference: Section 3 (core/validation.py), Section 13.2 (scan token limit note)
"""

from __future__ import annotations

import math
import re
import unicodedata

# Hard limit matching the API's client-side enforcement
MAX_INPUT_CHARS = 8000

# Server-side heuristic: ceil(len / 2) > 4000 -> 422
# CJK and dense text may be rejected below 8000 chars
TOKEN_HEURISTIC_LIMIT = 4000

# Session/run identifier constraints match the API's Pydantic validators.
# Opaque strings only; charset [A-Za-z0-9_.:-]; max 200 chars (Langfuse convention).
SESSION_ID_MAX_LEN = 200
SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:\-]+$")
TURN_INDEX_MAX     = 10000


def validate_session_id(value: str | None, field: str) -> str | None:
    """
    Validate a session_id or run_id field. Returns the value unchanged if
    valid, None if input is None. Raises ValueError on invalid input.

    Mirrors AIRequestSchema server-side rules so the SDK fails fast without
    a round-trip. Empty strings are rejected - callers must pass None to omit.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{field} must be non-empty; pass None to omit")
    if len(value) > SESSION_ID_MAX_LEN:
        raise ValueError(
            f"{field} exceeds max length of {SESSION_ID_MAX_LEN} chars "
            f"(got {len(value)})"
        )
    if not SESSION_ID_PATTERN.match(value):
        raise ValueError(
            f"{field} contains disallowed characters; allowed: [A-Za-z0-9_.:-]"
        )
    return value


def validate_turn_index(value: int | None) -> int | None:
    """Validate turn_index; mirrors AIRequestSchema server-side rules."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"turn_index must be an integer, got {type(value).__name__}")
    if value < 0 or value > TURN_INDEX_MAX:
        raise ValueError(f"turn_index must be in [0, {TURN_INDEX_MAX}], got {value}")
    return value


# Input provenance (trust boundary). Mirrors domain.enums.InputSource server-side.
VALID_INPUT_SOURCES = (
    "user_prompt", "tool_output", "retrieved_document", "external_content",
)


def validate_input_source(value: str) -> str:
    """Validate input_source; mirrors AIRequestSchema / InputSource. One of
    VALID_INPUT_SOURCES; defaults to user_prompt at the call site."""
    if value not in VALID_INPUT_SOURCES:
        raise ValueError(
            f"input_source must be one of {VALID_INPUT_SOURCES}, got {value!r}"
        )
    return value


def normalize_batch_items(
    items: list,
    default_source: str = "user_prompt",
) -> list[dict]:
    """
    Normalize a heterogeneous batch-scan input list into the wire shape the
    /v1/ai/scan-batch endpoint expects: [{input, input_source, id}, ...].

    Each item may be:
      - a plain string             -> input_source defaults to default_source
      - a dict {input|text, input_source?, id?}

    Text is normalized and length-validated per item (same rules as a single
    scan); input_source is validated against the allowed set. Idempotent, so a
    caller (or filter_safe) can pass an already-normalized list back through.
    """
    if not isinstance(items, (list, tuple)):
        raise ValueError(f"items must be a list, got {type(items).__name__}")

    normalized: list[dict] = []
    for idx, item in enumerate(items):
        if isinstance(item, str):
            text, source, item_id = item, default_source, None
        elif isinstance(item, dict):
            text = item.get("input", item.get("text"))
            if text is None:
                raise ValueError(f"batch item {idx} must have an 'input' (or 'text') field")
            source  = item.get("input_source") or default_source
            item_id = item.get("id")
        else:
            raise ValueError(
                f"batch item {idx} must be a str or dict, got {type(item).__name__}"
            )

        text   = validate_input(normalize_text(text))
        source = validate_input_source(source)
        normalized.append({"input": text, "input_source": source, "id": item_id})

    return normalized


def normalize_text(text: str) -> str:
    """
    Normalize input text before scanning.
    - NFKC unicode normalization
    - Normalize line endings to \\n
    - Strip leading/trailing whitespace
    - Remove ANSI escape codes
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\x1b\[[0-9;]*[mGKHF]", "", text)  # strip ANSI
    return text.strip()


def validate_input(text: str) -> str:
    """
    Validate scan input text.

    Raises ValueError with a clear message if:
      - text is empty after normalization
      - text exceeds MAX_INPUT_CHARS

    Returns the validated text (does not normalize - call normalize_text first).

    Spec: Section 13.2 - token limit note, Section 3 - validation in core/
    """
    if not text:
        raise ValueError("Input is empty.")

    if len(text) > MAX_INPUT_CHARS:
        raise ValueError(
            f"Input too large ({len(text):,} chars). "
            f"Maximum is {MAX_INPUT_CHARS:,} characters.\n"
            f"Note: For CJK or dense text, the server may reject inputs "
            f"shorter than {MAX_INPUT_CHARS:,} chars due to token estimation."
        )

    return text


def estimate_tokens(text: str) -> int:
    """
    Estimate token count using the server's heuristic: ceil(len / 2).
    Used for warnings - not enforced client-side.
    """
    return math.ceil(len(text) / 2)


def warn_if_dense(text: str) -> str | None:
    """
    Return a warning string if the text may be rejected by the server
    due to the token heuristic, even though it's under MAX_INPUT_CHARS.
    Returns None if no warning needed.
    """
    estimated = estimate_tokens(text)
    if estimated > TOKEN_HEURISTIC_LIMIT:
        return (
            f"Warning: estimated token count ({estimated}) may exceed the "
            f"server limit ({TOKEN_HEURISTIC_LIMIT}). "
            f"CJK or dense text may be rejected with HTTP 422."
        )
    return None
