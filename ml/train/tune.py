# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Hyperparameter tuning for the TF-IDF + Logistic Regression pipeline.

Uses GridSearchCV with stratified k-fold.
Tunes: C (regularisation), ngram_range, max_features.

Only run when explicitly called - not part of the default training pipeline.
Default parameters in pipeline.py are already well-calibrated.
"""

from __future__ import annotations

import logging

import numpy as np
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline

logger = logging.getLogger("wrapsec.ml.tune")


PARAM_GRID = {
    "tfidf__ngram_range":  [(1, 2), (1, 3)],
    "tfidf__max_features": [20_000, 50_000],
    "clf__C":              [0.1, 0.5, 1.0, 5.0],
}


def tune(
    pipeline: Pipeline,
    texts:    list[str],
    labels:   list[int],
    n_splits: int = 3,
) -> dict:
    """
    Run grid search to find best hyperparameters.
    Returns best params and best score.
    """
    logger.info("Running hyperparameter grid search...")
    logger.info(f"Grid: {PARAM_GRID}")

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    search = GridSearchCV(
        pipeline,
        PARAM_GRID,
        cv      = cv,
        scoring = "accuracy",
        n_jobs  = -1,
        verbose = 1,
        refit   = True,
    )

    search.fit(texts, labels)

    logger.info(f"\nBest params:  {search.best_params_}")
    logger.info(f"Best CV score: {search.best_score_:.3f}")

    return {
        "best_params": search.best_params_,
        "best_score":  search.best_score_,
        "best_pipeline": search.best_estimator_,
    }
