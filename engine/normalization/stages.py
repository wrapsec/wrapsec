# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Normalization stages. Each is self-describing (name, version, enabled) so the
pipeline version, metrics labels, and future config all derive from the stage
list. Order matters and is fixed by the STAGES list at the bottom.

Canonical stages (always-on, low-FPR) fold the text detection scans:
  strip_invisible -> nfkc -> fold_confusables -> collapse_whitespace
Lossy/ambiguous transforms (leetspeak, base64) are NOT folded in -- they emit
DetectionView candidates scanned separately, gated on a cheap signal so plain
text produces no extra views (and pays no extra latency).
"""

from __future__ import annotations

import base64
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

from engine.normalization import confusables
from engine.normalization.limits import MAX_DECODE_DEPTH
from engine.normalization.types import DetectionView, StageOutput


@dataclass(frozen=True)
class Stage:
    name:       str
    version:    str
    fn:         Callable[[str], StageOutput]
    enabled:    bool = True
    suspicious: bool = True   # firing signals obfuscation (False for mundane stages)


# --- canonical stages -------------------------------------------------

# Zero-width / format / bidi control code points used to hide or split payloads.
# Given as code points (ASCII-only source); translate deletes them.
_INVISIBLE: dict[int, None] = {cp: None for cp in (
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,  # ZWSP ZWNJ ZWJ WJ BOM SHY
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,          # bidi embeddings / overrides
    0x2066, 0x2067, 0x2068, 0x2069,                  # bidi isolates
)}


def _strip_invisible(text: str) -> StageOutput:
    out = text.translate(_INVISIBLE)
    return StageOutput(text=out, count=len(text) - len(out))


def _nfkc(text: str) -> StageOutput:
    out = unicodedata.normalize("NFKC", text)
    return StageOutput(text=out, count=0 if out == text else 1)


def _fold_confusables(text: str) -> StageOutput:
    out, count = confusables.fold_confusables(text)
    return StageOutput(text=out, count=count)


_WS = re.compile(r"\s+")


def _collapse_whitespace(text: str) -> StageOutput:
    out = _WS.sub(" ", text).strip()
    return StageOutput(text=out, count=0 if out == text else 1)


# --- view-producing stage (lossy decodings) ---------------------------

_LEET_TABLE  = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                              "7": "t", "8": "b", "9": "g", "@": "a", "$": "s"})
_LEET_SIGNAL = re.compile(r"[A-Za-z][0-9@$]|[0-9@$][A-Za-z]")   # digit/letter adjacency
_B64         = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(c.isprintable() or c in "\n\t " for c in s)
    return ok / len(s)


def _b64_views(segment: str, depth: int) -> list[DetectionView]:
    if depth > MAX_DECODE_DEPTH:
        return []
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except Exception:
        return []
    if _printable_ratio(decoded) < 0.7:      # binary junk -> not a hidden instruction
        return []
    views = [DetectionView(text=decoded, kind="base64", depth=depth)]
    for sub in _B64.findall(decoded):
        views.extend(_b64_views(sub, depth + 1))
    return views


def _decode_views(text: str) -> StageOutput:
    views: list[DetectionView] = []

    # leetspeak: only when digits/symbols sit adjacent to letters (cheap gate)
    if _LEET_SIGNAL.search(text):
        deleet = text.translate(_LEET_TABLE)
        if deleet != text:
            views.append(DetectionView(text=deleet, kind="leet", depth=0))

    # base64: only when a long base64-looking segment is present
    for segment in _B64.findall(text):
        views.extend(_b64_views(segment, depth=1))

    return StageOutput(views=tuple(views), count=len(views))


# --- ordered pipeline -------------------------------------------------
# Extend by appending (language_normalize, hex/url/gzip views, ...). The version
# is derived from this list, so a change here bumps the pipeline version.

STAGES: list[Stage] = [
    Stage("strip_invisible",     "1", _strip_invisible),
    Stage("nfkc",                "1", _nfkc, suspicious=False),
    Stage("fold_confusables",    confusables.VERSION, _fold_confusables),
    Stage("collapse_whitespace", "1", _collapse_whitespace, suspicious=False),
    Stage("decode_views",        "1", _decode_views),
]
