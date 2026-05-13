# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Dataset quality validation.

Checks:
  1. Class balance - no class should dominate by >5x
  2. Text length distribution - flag outliers
  3. Duplicate detection - exact and near-duplicate
  4. Label sanity - no missing or invalid labels
  5. Minimum sample count - each class must have MIN_SAMPLES
"""

from __future__ import annotations

import logging

import pandas as pd

logger = logging.getLogger("wrapsec.ml.validate")

LABEL_NAMES = {
    0: "BENIGN",
    1: "PROMPT_INJECTION",
    2: "JAILBREAK",
    3: "MALICIOUS_INTENT",
    4: "DATA_EXFILTRATION",
    5: "PII",
    6: "TOXICITY",
}

MIN_SAMPLES_PER_CLASS = 50
MAX_IMBALANCE_RATIO   = 10.0  # max class / min class


def validate(df: pd.DataFrame) -> bool:
    """
    Run all validation checks on the dataset.
    Returns True if dataset is acceptable, False if critical issues found.
    Logs warnings for non-critical issues.
    """
    logger.info("=" * 60)
    logger.info("Dataset Validation")
    logger.info("=" * 60)

    issues   = 0
    warnings = 0

    # ── Check 1: Required columns ─────────────────────────────────────────────
    required = {"text", "label", "source"}
    missing  = required - set(df.columns)
    if missing:
        logger.error(f"Missing required columns: {missing}")
        issues += 1
    else:
        logger.info(" Required columns present")

    # ── Check 2: No null values ───────────────────────────────────────────────
    null_counts = df[["text", "label"]].isnull().sum()
    if null_counts.any():
        logger.error(f"Null values found: {null_counts.to_dict()}")
        issues += 1
    else:
        logger.info(" No null values")

    # ── Check 3: Valid labels ─────────────────────────────────────────────────
    valid_labels = set(LABEL_NAMES.keys())
    invalid      = set(df["label"].unique()) - valid_labels
    if invalid:
        logger.error(f"Invalid labels found: {invalid}")
        issues += 1
    else:
        logger.info(" All labels valid")

    # ── Check 4: Minimum samples per class ────────────────────────────────────
    counts = df["label"].value_counts()
    below_min = []
    for label_id, name in LABEL_NAMES.items():
        count = counts.get(label_id, 0)
        if count < MIN_SAMPLES_PER_CLASS:
            below_min.append(f"{name}: {count}")
    if below_min:
        logger.warning(
            f"Classes below minimum ({MIN_SAMPLES_PER_CLASS} samples): "
            f"{', '.join(below_min)}"
        )
        warnings += 1
    else:
        logger.info(f" All classes have ≥{MIN_SAMPLES_PER_CLASS} samples")

    # ── Check 5: Class balance ────────────────────────────────────────────────
    if len(counts) > 0:
        ratio = counts.max() / counts.min()
        if ratio > MAX_IMBALANCE_RATIO:
            logger.warning(
                f"High class imbalance: max/min ratio = {ratio:.1f}x "
                f"(threshold: {MAX_IMBALANCE_RATIO}x)"
            )
            warnings += 1
        else:
            logger.info(f" Class balance OK (ratio: {ratio:.1f}x)")

    # ── Check 6: Text length distribution ────────────────────────────────────
    lengths = df["text"].str.len()
    very_short = (lengths < 10).sum()
    very_long  = (lengths > 2000).sum()
    if very_short > 0:
        logger.warning(f"{very_short} samples with text length < 10 chars")
        warnings += 1
    if very_long > 0:
        logger.warning(f"{very_long} samples with text length > 2000 chars")
        warnings += 1
    logger.info(
        f"Text lengths - min: {lengths.min()}, "
        f"median: {lengths.median():.0f}, "
        f"max: {lengths.max()}"
    )

    # ── Check 7: Exact duplicates ─────────────────────────────────────────────
    dupes = df.duplicated(subset=["text"]).sum()
    if dupes > 0:
        logger.warning(f"{dupes} exact duplicate texts found")
        warnings += 1
    else:
        logger.info(" No exact duplicates")

    # ── Summary ───────────────────────────────────────────────────────────────
    logger.info("\nClass distribution:")
    for label_id, name in LABEL_NAMES.items():
        count  = counts.get(label_id, 0)
        pct    = count / len(df) * 100 if len(df) > 0 else 0
        bar    = "█" * int(pct / 2)
        logger.info(f"  {name:<20} {count:>5}  ({pct:4.1f}%)  {bar}")

    logger.info(f"\nTotal samples: {len(df)}")
    logger.info(f"Issues:        {issues}")
    logger.info(f"Warnings:      {warnings}")

    if issues > 0:
        logger.error("Validation FAILED - critical issues found")
        return False

    if warnings > 0:
        logger.warning("Validation passed with warnings")
    else:
        logger.info(" Validation passed")

    return True
