# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Cross-script confusable (homoglyph) folding.

NFKC does NOT collapse most confusables (Cyrillic U+0430 has no NFKC mapping to
Latin 'a'), so an NFKC-only pipeline stays fully exposed to the highest-yield
evasion family. This is a curated TR39-style skeleton for the high-value
Latin-look-alike scripts (Cyrillic, Greek), built into one translate table so
folding is a single C-level pass.

Defined as (code point, ASCII) pairs so the source stays ASCII-only and every
mapping is reviewable by its hex code point (no look-alike characters in source).
Curated, not the full Unicode confusables set -- extend as new families appear
in evaluation.
"""

from __future__ import annotations

# (confusable code point, ASCII letter it imitates)
_PAIRS: list[tuple[int, str]] = [
    # Cyrillic lowercase
    (0x0430, "a"), (0x0435, "e"), (0x043E, "o"), (0x0440, "p"), (0x0441, "c"),
    (0x0443, "y"), (0x0445, "x"), (0x0456, "i"), (0x0455, "s"), (0x04BB, "h"),
    (0x0501, "d"), (0x043A, "k"), (0x0442, "t"), (0x043C, "m"), (0x043D, "n"),
    (0x0432, "b"),
    # Cyrillic uppercase
    (0x0410, "A"), (0x0412, "B"), (0x0415, "E"), (0x041A, "K"), (0x041C, "M"),
    (0x041D, "H"), (0x041E, "O"), (0x0420, "P"), (0x0421, "C"), (0x0422, "T"),
    (0x0423, "Y"), (0x0425, "X"),
    # Greek lowercase
    (0x03BF, "o"), (0x03B1, "a"), (0x03B5, "e"), (0x03BD, "v"), (0x03C1, "p"),
    (0x03C4, "t"), (0x03B9, "i"), (0x03BA, "k"), (0x03C5, "u"),
    # Greek uppercase
    (0x039F, "O"), (0x0391, "A"), (0x0395, "E"), (0x03A1, "P"), (0x03A4, "T"),
    (0x0392, "B"), (0x0397, "H"), (0x039A, "K"), (0x039C, "M"), (0x039D, "N"),
    (0x0396, "Z"), (0x0399, "I"), (0x03A7, "X"), (0x03A5, "Y"),
    # strays
    (0x0131, "i"),   # dotless i
]

# str.translate accepts a {ordinal: str} table directly.
_TABLE: dict[int, str] = {cp: ascii_ch for cp, ascii_ch in _PAIRS}

# Bump when the map changes so the pipeline version tracks it.
VERSION = "1"


def fold_confusables(text: str) -> tuple[str, int]:
    """Fold confusables to ASCII. Returns (folded, changed_char_count). The map
    is 1:1 so length is preserved and the count is an exact char diff."""
    folded = text.translate(_TABLE)
    if folded == text:
        return text, 0
    count = sum(1 for a, b in zip(text, folded) if a != b)
    return folded, count
