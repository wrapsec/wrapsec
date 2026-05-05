# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Input validation — length limits, token estimate, charset normalisation.

Called by client before sending to API — never duplicated in CLI commands.

Spec reference: Section 3 (core/validation.py), Section 13.2 (scan token limit note)
"""

from __future__ import annotations

import math
import re
import unicodedata

# Hard limit matching the API's client-side enforcement
MAX_INPUT_CHARS = 8000

# Server-side heuristic: ceil(len / 2) > 4000 → 422
# CJK and dense text may be rejected below 8000 chars
TOKEN_HEURISTIC_LIMIT = 4000


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

    Returns the validated text (does not normalize — call normalize_text first).

    Spec: Section 13.2 — token limit note, Section 3 — validation in core/
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
    Used for warnings — not enforced client-side.
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
