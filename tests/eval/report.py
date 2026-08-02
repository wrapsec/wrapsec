# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Human-readable rendering of the metrics dict from tests.eval.metrics."""

from __future__ import annotations


def format_report(m: dict) -> str:
    o     = m["overall"]
    lines = ["=== WrapSec red-team evaluation ==="]
    lines.append(
        f"cases: {m['counts']['total']} "
        f"({m['counts']['malicious']} malicious, {m['counts']['benign']} benign)"
    )
    lines.append("")
    lines.append(f"catch-rate (TPR):      {o['catch_rate']:.1%}   (block-rate {o['block_rate']:.1%})")
    lines.append(f"false-positive (FPR):  {o['fpr']:.1%}")
    lines.append(f"  benign-hard FPR:     {m['over_defense']['benign_hard_fpr']:.1%}   <- over-defense")
    lines.append(f"precision / recall:    {o['precision']:.1%} / {o['recall']:.1%}")
    lines.append(f"F1:                    {o['f1']:.3f}")
    lines.append(f"OOD catch-rate:        {m['ood']['catch_rate']:.1%}   (n={m['ood']['n']})")
    lines.append("")

    lines.append("by group:")
    for g, d in sorted(m["by_group"].items()):
        if d["label"] == "malicious":
            lines.append(f"  {g:22} catch {d['catch_rate']:6.1%}  ({d['flagged']}/{d['n']})")
        else:
            lines.append(f"  {g:22} fpr   {d['fpr']:6.1%}  ({d['flagged']}/{d['n']})")
    lines.append("")

    if m["bypasses"]:
        lines.append(f"BYPASSES ({len(m['bypasses'])} attacks got through):")
        for b in m["bypasses"]:
            lines.append(f"  [{b['id']}] {b['category']}: {b['text'][:70]}")
    else:
        lines.append("BYPASSES: none")
    lines.append("")

    if m["false_positives"]:
        lines.append(f"FALSE POSITIVES ({len(m['false_positives'])} benign flagged):")
        for f in m["false_positives"]:
            lines.append(f"  [{f['id']}] ({f['group']}, score {f['score']:.2f}): {f['text'][:70]}")
    else:
        lines.append("FALSE POSITIVES: none")
    lines.append("")

    lines.append("threshold sweep (score-approx TPR/FPR):")
    for s in m["threshold_sweep"]:
        lines.append(f"  t={s['threshold']:.1f}  tpr {s['tpr']:6.1%}  fpr {s['fpr']:6.1%}")
    return "\n".join(lines)
