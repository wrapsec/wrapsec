#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
What scanning assistant history would cost, measured on its own corpus.

Assistant scanning is an opt-in capability that ships disabled. These cases are
held apart from the gated corpus for one reason: mixing them in would move the
established baseline, and a baseline that moves for a reason unrelated to the
detectors stops being a regression guard. Keeping them separate means the
established gate keeps measuring what it has always measured, and this number
stays visible instead of being averaged away.

This is a MEASUREMENT, not a gate. It reports and always exits 0, because a
failing exit here would block work on a capability that is off by default. The
number it prints is what has to come down before the capability can be turned
on -- the enablement target is 12% false positives on this corpus, and the
malicious cases must keep being caught.

Run it:

    python tests/eval/run_assistant_eval.py
    python tests/eval/run_assistant_eval.py --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

os.environ.setdefault("TESTING", "true")

from tests.eval.runner import run_corpus
from tests.eval.schema import load_corpus

CORPUS_ASSISTANT_DIR = Path(__file__).parent / "corpus_assistant"

# What the false-positive rate has to reach before the capability can default
# on. Stated here rather than enforced: see the module docstring.
ENABLEMENT_FPR_TARGET = 0.12


def _measure(results) -> dict:
    benign    = [r for r in results if r.case.label == "benign"]
    malicious = [r for r in results if r.case.label == "malicious"]

    flagged_benign    = [r for r in benign    if r.flagged]
    missed_malicious  = [r for r in malicious if not r.flagged]

    return {
        "benign":            len(benign),
        "malicious":         len(malicious),
        "fpr":               (len(flagged_benign) / len(benign)) if benign else 0.0,
        "catch_rate":        ((len(malicious) - len(missed_malicious)) / len(malicious))
                             if malicious else 0.0,
        "false_positives":   [
            {"id": r.case.id, "score": r.risk_score, "reason": r.primary_reason,
             "text": r.case.text[:70]}
            for r in flagged_benign
        ],
        "missed":            [
            {"id": r.case.id, "text": r.case.text[:70]} for r in missed_malicious
        ],
        "enablement_target": ENABLEMENT_FPR_TARGET,
        "meets_target":      (len(flagged_benign) / len(benign)) <= ENABLEMENT_FPR_TARGET
                             if benign else False,
    }


def _format(m: dict) -> str:
    lines = [
        "",
        "=== Assistant-prose evaluation (opt-in capability, disabled by default) ===",
        (f"cases: {m['benign'] + m['malicious']} "
         f"({m['malicious']} malicious, {m['benign']} benign)"),
        "",
        (f"false-positive (FPR):  {m['fpr']:.1%}   "
         f"target for enablement <= {m['enablement_target']:.0%}   "
         f"[{'MEETS TARGET' if m['meets_target'] else 'DOES NOT MEET TARGET'}]"),
        f"catch-rate (TPR):      {m['catch_rate']:.1%}",
    ]

    if m["false_positives"]:
        lines += ["", f"FALSE POSITIVES ({len(m['false_positives'])} benign assistant turns flagged):"]
        lines += [f"  [{f['id']}] score {f['score']:.2f} via {f['reason']}: {f['text']}"
                  for f in m["false_positives"]]
    if m["missed"]:
        lines += ["", f"MISSED ({len(m['missed'])} malicious assistant turns got through):"]
        lines += [f"  [{f['id']}] {f['text']}" for f in m["missed"]]

    lines += [
        "",
        "This is a measurement, not a gate. The established corpus keeps its own",
        "ceiling and is unaffected by these cases. Assistant scanning stays off",
        "until the rate above reaches the target.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    cases   = load_corpus(CORPUS_ASSISTANT_DIR)
    results = asyncio.run(run_corpus(cases))
    metrics = _measure(results)

    print(json.dumps(metrics, indent=2) if args.json else _format(metrics))
    # Always 0: a capability that is off by default must not fail the build.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
