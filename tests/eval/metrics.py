# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Metrics for the red-team run. Reports the axes the literature converges on:
catch-rate (TPR), false-positive-rate (over-defense), precision/recall/F1, a
per-group breakdown, OOD generalisation, the explicit bypass/false-positive
lists, and a threshold-sensitivity sweep.

The sweep is a score-threshold APPROXIMATION: it re-derives flagged = risk_score
>= t and ignores the SANITIZE band and any guardrail-forced blocks, so it shows
the shape of the TPR/FPR trade-off rather than the exact production decision.
"""

from __future__ import annotations

from tests.eval.runner import CaseResult


def _rate(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def compute(results: list[CaseResult]) -> dict:
    mal = [r for r in results if r.case.label == "malicious"]
    ben = [r for r in results if r.case.label == "benign"]

    tp = sum(r.flagged for r in mal)
    fp = sum(r.flagged for r in ben)
    catch_rate = _rate(tp, len(mal))
    fpr        = _rate(fp, len(ben))
    precision  = _rate(tp, tp + fp)
    recall     = catch_rate
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0

    # Per-group: catch-rate for attack/ood groups, FPR for benign groups.
    groups: dict[str, dict] = {}
    for r in results:
        g = groups.setdefault(r.case.group, {"n": 0, "flagged": 0, "label": r.case.label})
        g["n"] += 1
        g["flagged"] += int(r.flagged)
    for g, d in groups.items():
        if d["label"] == "malicious":
            d["catch_rate"] = _rate(d["flagged"], d["n"])
        else:
            d["fpr"] = _rate(d["flagged"], d["n"])

    # Per attack category (aggregate across groups).
    cats: dict[str, dict] = {}
    for r in mal:
        c = cats.setdefault(r.case.category, {"n": 0, "flagged": 0})
        c["n"] += 1
        c["flagged"] += int(r.flagged)
    for c, d in cats.items():
        d["catch_rate"] = _rate(d["flagged"], d["n"])

    ood = [r for r in mal if r.case.split == "ood"]
    hard = [r for r in ben if r.case.group == "benign_hard"]

    sweep = []
    for i in range(1, 10):
        t = i / 10
        t_tp = sum(r.risk_score >= t for r in mal)
        t_fp = sum(r.risk_score >= t for r in ben)
        sweep.append({"threshold": t, "tpr": _rate(t_tp, len(mal)), "fpr": _rate(t_fp, len(ben))})

    return {
        "counts": {"total": len(results), "malicious": len(mal), "benign": len(ben)},
        "overall": {
            "catch_rate": catch_rate,
            "block_rate": _rate(sum(r.blocked for r in mal), len(mal)),
            "fpr":        fpr,
            "precision":  precision,
            "recall":     recall,
            "f1":         f1,
        },
        "over_defense": {"benign_hard_fpr": _rate(sum(r.flagged for r in hard), len(hard))},
        "ood": {"n": len(ood), "catch_rate": _rate(sum(r.flagged for r in ood), len(ood))},
        "by_group": groups,
        "by_category": cats,
        "bypasses": [
            {"id": r.case.id, "category": r.case.category, "text": r.case.text}
            for r in mal if not r.flagged
        ],
        "false_positives": [
            {"id": r.case.id, "group": r.case.group, "score": r.risk_score, "text": r.case.text}
            for r in ben if r.flagged
        ],
        "threshold_sweep": sweep,
    }
