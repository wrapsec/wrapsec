# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Corpus schema and loader for the red-team / guardrail-evaluation harness.

Each corpus file is JSON Lines (one object per line) under corpus/<split>/.
A line needs only `id`, `text`, `category`, and `label`; `split` is inferred
from the directory, and `source`/`license` default to WrapSec-authored / MIT so
the committed corpus stays license-clean for an OSS repo.

Labels drive the pass/fail expectation:
  malicious -> the detector SHOULD flag it (decision BLOCK or SANITIZE)
  benign    -> the detector should NOT flag it (decision ALLOW)

`category` is a domain.enums.ThreatCategory value (or BENIGN) so results can be
broken down against WrapSec's own taxonomy rather than a forked one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"

_VALID_LABELS = {"malicious", "benign"}


@dataclass(frozen=True)
class Case:
    id:       str
    text:     str
    category: str          # ThreatCategory value, or "BENIGN"
    label:    str          # "malicious" | "benign"
    split:    str          # "attacks" | "benign" | "ood" (from the directory)
    source:   str = "wrapsec-authored"
    license:  str = "MIT"


def load_corpus(corpus_dir: Path | None = None) -> list[Case]:
    """Load every corpus/<split>/*.jsonl case. Raises on malformed lines or
    duplicate ids so a bad corpus fails loudly rather than skewing metrics."""
    root  = corpus_dir or CORPUS_DIR
    cases: list[Case] = []
    seen:  set[str]   = set()

    for path in sorted(root.glob("*/*.jsonl")):
        split = path.parent.name
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno} invalid JSON: {exc}") from exc

            missing = {"id", "text", "category", "label"} - obj.keys()
            if missing:
                raise ValueError(f"{path}:{lineno} missing fields: {sorted(missing)}")
            if obj["label"] not in _VALID_LABELS:
                raise ValueError(f"{path}:{lineno} bad label {obj['label']!r}")
            if obj["id"] in seen:
                raise ValueError(f"{path}:{lineno} duplicate id {obj['id']!r}")
            seen.add(obj["id"])

            cases.append(Case(
                id       = obj["id"],
                text     = obj["text"],
                category = obj["category"],
                label    = obj["label"],
                split    = split,
                source   = obj.get("source", "wrapsec-authored"),
                license  = obj.get("license", "MIT"),
            ))

    if not cases:
        raise ValueError(f"no corpus cases found under {root}")
    return cases
