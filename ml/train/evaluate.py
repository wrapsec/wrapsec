# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Model evaluation — cross-validation, per-class metrics, confusion matrix.

Produces:
  - 5-fold stratified cross-validation accuracy
  - Per-class precision, recall, F1
  - Confusion matrix
  - Confidence calibration check
  - False positive analysis (benign samples misclassified)
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline

logger = logging.getLogger("wrapsec.ml.evaluate")

LABEL_NAMES = {
    0: "BENIGN",
    1: "PROMPT_INJECTION",
    2: "JAILBREAK",
    3: "MALICIOUS_INTENT",
    4: "DATA_EXFILTRATION",
    5: "PII",
    6: "TOXICITY",
}

TARGET_ACCURACY = 0.85  # minimum acceptable cross-val accuracy
TARGET_F1_MIN   = 0.70  # minimum acceptable F1 per class


def cross_validate(
    pipeline: Pipeline,
    texts:    list[str],
    labels:   list[int],
    n_splits: int = 5,
) -> dict:
    """
    Run stratified k-fold cross-validation.
    Returns dict with mean, std, and per-fold scores.
    """
    logger.info(f"\nRunning {n_splits}-fold stratified cross-validation...")

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scores = cross_val_score(
        pipeline, texts, labels,
        cv      = cv,
        scoring = "accuracy",
        n_jobs  = -1,
    )

    result = {
        "scores": scores.tolist(),
        "mean":   float(scores.mean()),
        "std":    float(scores.std()),
        "min":    float(scores.min()),
        "max":    float(scores.max()),
    }

    logger.info(f"CV Accuracy: {result['mean']:.3f} ± {result['std']:.3f}")
    logger.info(f"  Per fold:  {[f'{s:.3f}' for s in scores]}")

    if result["mean"] < TARGET_ACCURACY:
        logger.warning(
            f"⚠ CV accuracy {result['mean']:.3f} is below target {TARGET_ACCURACY}. "
            f"Consider more training data or hyperparameter tuning."
        )
    else:
        logger.info(f"✔ CV accuracy meets target ({TARGET_ACCURACY})")

    return result


def evaluate_on_holdout(
    pipeline:      Pipeline,
    texts_test:    list[str],
    labels_test:   list[int],
) -> dict:
    """
    Evaluate the trained pipeline on a held-out test set.
    Returns classification report and confusion matrix.
    """
    logger.info("\nEvaluating on held-out test set...")

    labels_pred = pipeline.predict(texts_test)
    label_names = [LABEL_NAMES[i] for i in sorted(LABEL_NAMES.keys())]

    # Classification report
    report = classification_report(
        labels_test,
        labels_pred,
        target_names = label_names,
        output_dict  = True,
    )

    logger.info("\nPer-class metrics:")
    logger.info(f"{'Class':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    logger.info("-" * 55)

    low_f1_classes = []
    for label_id, name in LABEL_NAMES.items():
        if name in report:
            p = report[name]["precision"]
            r = report[name]["recall"]
            f = report[name]["f1-score"]
            s = report[name]["support"]
            flag = " ⚠" if f < TARGET_F1_MIN else ""
            logger.info(f"{name:<20} {p:>10.3f} {r:>10.3f} {f:>10.3f} {s:>10.0f}{flag}")
            if f < TARGET_F1_MIN:
                low_f1_classes.append(name)

    logger.info("-" * 55)
    acc = report.get("accuracy", 0)
    logger.info(f"{'Overall accuracy':<20} {acc:>10.3f}")

    if low_f1_classes:
        logger.warning(
            f"⚠ Classes with F1 below {TARGET_F1_MIN}: {', '.join(low_f1_classes)}"
        )

    # Confusion matrix
    cm = confusion_matrix(labels_test, labels_pred)
    logger.info("\nConfusion matrix (rows=actual, cols=predicted):")
    logger.info(f"{'':>5} " + " ".join(f"{LABEL_NAMES[i][:4]:>6}" for i in sorted(LABEL_NAMES)))
    for i, row in enumerate(cm):
        logger.info(f"{LABEL_NAMES[i][:4]:>5} " + " ".join(f"{v:>6}" for v in row))

    # False positive analysis — benign samples misclassified
    benign_mask = [l == 0 for l in labels_test]
    benign_texts  = [t for t, m in zip(texts_test, benign_mask) if m]
    benign_labels = [l for l, m in zip(labels_test, benign_mask) if m]
    benign_preds  = [p for p, m in zip(labels_pred, benign_mask) if m]

    false_positives = [
        (t, p) for t, a, p in zip(benign_texts, benign_labels, benign_preds)
        if a != p
    ]

    if false_positives:
        logger.warning(f"\n⚠ {len(false_positives)} benign samples misclassified (false positives):")
        for text, pred in false_positives[:5]:  # show first 5
            logger.warning(f"  [{LABEL_NAMES[pred]}] {text[:80]}")
    else:
        logger.info("\n✔ No benign samples misclassified (zero false positives on test set)")

    return {
        "accuracy":       acc,
        "report":         report,
        "confusion_matrix": cm.tolist(),
        "false_positives": len(false_positives),
        "low_f1_classes": low_f1_classes,
    }


def confidence_check(
    pipeline: Pipeline,
    texts:    list[str],
    labels:   list[int],
    sample_n: int = 20,
) -> None:
    """
    Spot-check confidence scores on a random sample of test inputs.
    Flags predictions with low confidence (< 0.5) that are still correct.
    """
    logger.info(f"\nConfidence spot-check ({sample_n} random samples):")

    import random
    random.seed(42)
    indices = random.sample(range(len(texts)), min(sample_n, len(texts)))

    probas = pipeline.predict_proba([texts[i] for i in indices])

    low_confidence = 0
    for idx, proba in zip(indices, probas):
        pred_class = proba.argmax()
        confidence = proba[pred_class]
        actual     = labels[idx]
        correct    = pred_class == actual
        flag       = "" if correct and confidence >= 0.5 else " ⚠ LOW CONF"

        if not correct or confidence < 0.5:
            logger.info(
                f"  {'✔' if correct else '✗'} "
                f"actual={LABEL_NAMES[actual][:12]:<12} "
                f"pred={LABEL_NAMES[pred_class][:12]:<12} "
                f"conf={confidence:.2f}{flag}"
            )
            if confidence < 0.5:
                low_confidence += 1

    if low_confidence > 0:
        logger.warning(f"⚠ {low_confidence} predictions with confidence < 0.5")
