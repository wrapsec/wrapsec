# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Source-aware posture calibration.

Sweeps untrusted_threshold_delta over the RAG corpus (corpus_rag/) and reports,
per delta, the poisoned-document catch-rate and the RAG-benign false-positive
rate. The RAG cases are input_source=retrieved_document, so a non-zero delta
lowers the block/sanitize thresholds ONLY for them (trusted user_prompt traffic
is unaffected).

This corpus is deliberately SEPARATE from the main red-team gate corpus: mixing
attack-discussion benign docs into the gate would move its numbers. Here they
are exactly the over-defense probe we want.

    python tests/eval/calibrate_source_posture.py
    python tests/eval/calibrate_source_posture.py --json

Use it to choose a RECOMMENDED delta (raises poisoned catch while holding the
benign FPR at or below the delta=0 baseline). The default ships as 0 (opt-in).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.eval.runner import run_corpus
from tests.eval.schema import load_corpus

CORPUS_RAG_DIR = Path(__file__).parent / "corpus_rag"
DELTAS = [0.0, 0.05, 0.10, 0.15, 0.20, 0.30]


def _rate(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


async def _measure(cases, delta: float) -> dict:
    # Per-call settings read in the gateway picks this up once the cache is
    # cleared; keep the run hermetic.
    os.environ["UNTRUSTED_THRESHOLD_DELTA"] = str(delta)
    from config.settings import get_settings
    get_settings.cache_clear()

    results = await run_corpus(cases)
    mal = [r for r in results if r.case.label == "malicious"]
    ben = [r for r in results if r.case.label == "benign"]
    return {
        "delta":           delta,
        "poisoned_catch":  _rate(sum(r.flagged for r in mal), len(mal)),
        "benign_fpr":      _rate(sum(r.flagged for r in ben), len(ben)),
        "poisoned_n":      len(mal),
        "benign_n":        len(ben),
    }


def _recommend(rows: list[dict]) -> float:
    """Largest delta whose benign FPR stays at or below the delta=0 baseline,
    preferring the one with the highest poisoned catch. Falls back to 0.0."""
    baseline_fpr = next(r["benign_fpr"] for r in rows if r["delta"] == 0.0)
    eligible = [r for r in rows if r["benign_fpr"] <= baseline_fpr]
    if not eligible:
        return 0.0
    best = max(eligible, key=lambda r: (r["poisoned_catch"], -r["delta"]))
    return best["delta"]


async def _run() -> dict:
    cases = load_corpus(CORPUS_RAG_DIR)
    rows  = [await _measure(cases, d) for d in DELTAS]
    return {"sweep": rows, "recommended_delta": _recommend(rows)}


def _format(report: dict) -> str:
    lines = [
        "Source-aware posture calibration (corpus_rag/)",
        "=" * 52,
        f"{'delta':>7}  {'poisoned catch':>15}  {'benign FPR':>11}",
        "-" * 52,
    ]
    for r in report["sweep"]:
        lines.append(f"{r['delta']:>7.2f}  {r['poisoned_catch']:>14.1%}  {r['benign_fpr']:>10.1%}")
    lines += [
        "-" * 52,
        f"poisoned docs: {report['sweep'][0]['poisoned_n']}   "
        f"benign docs: {report['sweep'][0]['benign_n']}",
        f"RECOMMENDED untrusted_threshold_delta: {report['recommended_delta']:.2f} "
        f"(default ships as 0.00 / opt-in)",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Source-aware posture calibration")
    parser.add_argument("--json", action="store_true", help="emit the sweep as JSON")
    args = parser.parse_args()

    os.environ.setdefault("TESTING", "true")
    report = asyncio.run(_run())
    print(json.dumps(report, indent=2) if args.json else _format(report))


if __name__ == "__main__":
    main()
