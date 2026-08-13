# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Red-team / guardrail-evaluation CLI.

Runs the committed corpus through WrapSec's detection (FAST, offline) and prints
the report. Publishable trust signal and the input to the CI regression gate.

    python tests/eval/run_evaluation.py            # human report
    python tests/eval/run_evaluation.py --json     # machine-readable metrics
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Allow `python tests/eval/run_evaluation.py` (direct-script run puts this file's
# directory on sys.path, not the repo root) in addition to `-m tests.eval...`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.eval.metrics import compute
from tests.eval.report import format_report
from tests.eval.runner import run_corpus


def main() -> None:
    parser = argparse.ArgumentParser(description="WrapSec red-team evaluation")
    parser.add_argument("--json", action="store_true", help="emit the metrics dict as JSON")
    args = parser.parse_args()

    os.environ.setdefault("TESTING", "true")  # keep the run hermetic (no lifespan side effects)

    results = asyncio.run(run_corpus())
    metrics = compute(results)

    print(json.dumps(metrics, indent=2) if args.json else format_report(metrics))


if __name__ == "__main__":
    main()
