# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import numpy as np


def detector_confidence(
    rule_score:   float,
    ml_score:     float,
    llm_score:    float,
    rule_enabled: bool = True,
    ml_enabled:   bool = True,
    llm_invoked:  bool = False,
) -> float:
    """
    Measures agreement across invoked detection layers.
    Uses scaled inverse variance for meaningful differentiation.

    Only includes layers that were actually invoked -
    prevents false variance inflation when LLM is skipped.
    """
    invoked_scores = []
    if rule_enabled:
        invoked_scores.append(rule_score)
    if ml_enabled:
        invoked_scores.append(ml_score)
    if llm_invoked:
        invoked_scores.append(llm_score)

    if len(invoked_scores) == 0:
        return 1.0

    if len(invoked_scores) == 1:
        # Single layer - no variance possible
        # Confidence equals the score itself if high, else moderate
        return 1.0

    variance   = float(np.var(invoked_scores))
    confidence = 1 / (1 + variance * 5)

    # Confidence floor for strong signals
    # A strong rule match should not be downgraded to MEDIUM
    # purely because probabilistic layers disagree
    max_score = max(invoked_scores)
    if max_score >= 0.8:
        confidence = max(confidence, 0.75)

    return round(confidence, 4)


def guardrail_confidence(
    pii_score:          float,
    block_threshold:    float = 0.7,
    sanitize_threshold: float = 0.4,
) -> float:
    """
    Guardrails are deterministic - confidence is always high.
    Tiered model reflects semantic difference between
    BLOCK and SANITIZE decisions.

    BLOCK level:    0.90 - 0.95
    SANITIZE level: 0.70 - 0.84
    No guardrail:   0.0
    """
    if pii_score >= block_threshold:
        # BLOCK-level PII - very high confidence
        raw = 0.90 + (min(pii_score, 1.0) - block_threshold) * 0.05
        return round(min(raw, 0.95), 4)

    elif pii_score >= sanitize_threshold:
        # SANITIZE-level PII - medium-high confidence
        raw = 0.70 + (pii_score - sanitize_threshold) * 0.20
        return round(min(raw, 0.84), 4)

    return 0.0


def compute_confidence(
    rule_score:                  float,
    ml_score:                    float,
    llm_score:                   float,
    pii_score:                   float,
    rule_enabled:                bool  = True,
    ml_enabled:                  bool  = True,
    llm_invoked:                 bool  = False,
    guardrail_triggered:         bool  = False,
    block_threshold:             float = 0.7,
    sanitize_threshold:          float = 0.4,
    toxicity_score:              float = 0.0,
    toxicity_guardrail_triggered: bool = False,
) -> tuple[float, str]:
    """
    Returns (confidence, confidence_band).

    Priority:
      1. PII guardrail triggered      -> guardrail_confidence(pii_score)
      2. Toxicity guardrail triggered -> guardrail_confidence(toxicity_score)
      3. Detection-based              -> detector_confidence(rule/ml/llm)
    """
    if guardrail_triggered:
        confidence = guardrail_confidence(
            pii_score          = pii_score,
            block_threshold    = block_threshold,
            sanitize_threshold = sanitize_threshold,
        )
    elif toxicity_guardrail_triggered:
        confidence = guardrail_confidence(
            pii_score          = toxicity_score,
            block_threshold    = block_threshold,
            sanitize_threshold = sanitize_threshold,
        )
    else:
        confidence = detector_confidence(
            rule_score   = rule_score,
            ml_score     = ml_score,
            llm_score    = llm_score,
            rule_enabled = rule_enabled,
            ml_enabled   = ml_enabled,
            llm_invoked  = llm_invoked,
        )

    confidence = round(min(confidence, 1.0), 4)
    band       = get_confidence_band(confidence)

    return confidence, band


def get_confidence_band(confidence: float) -> str:
    if confidence >= 0.7:
        return "HIGH"
    if confidence >= 0.4:
        return "MEDIUM"
    return "LOW"