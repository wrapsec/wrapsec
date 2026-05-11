# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

def compute_primary_reason(
    guardrail_triggered:          bool,
    guardrail_decision:           str | None,
    rule_score:                   float,
    ml_score:                     float,
    llm_score:                    float,
    pii_score:                    float,
    block_threshold:              float = 0.7,
    sanitize_threshold:           float = 0.4,
    detection_failed:             bool  = False,
    toxicity_score:               float = 0.0,
    toxicity_guardrail_triggered: bool  = False,
    toxicity_block_threshold:     float | None = None,
) -> str:
    """
    Determines the dominant factor behind the decision.

    Priority:
      1. System/detection failure        -> SYSTEM_ERROR
      2. PII guardrail triggered         -> PII_GUARDRAIL_BLOCK or PII_GUARDRAIL_SANITIZE
      3. Toxicity guardrail triggered    -> TOXICITY_GUARDRAIL_BLOCK or TOXICITY_GUARDRAIL_SANITIZE
      4. Highest detector score          -> RULE_DETECTOR / ML_DETECTOR / LLM_DETECTOR
      5. No threat detected              -> NO_THREAT_DETECTED

    Note: SYSTEM_ERROR takes absolute priority.
    Note: PII guardrail takes priority over toxicity guardrail.
    Note: _GUARDRAIL_BLOCK suffix auto-classifies as CRITICAL severity.
    """

    # System failure takes absolute priority
    if detection_failed:
        return "SYSTEM_ERROR"

    # PII guardrail - first guardrail priority
    if guardrail_triggered:
        if pii_score >= block_threshold:
            return "PII_GUARDRAIL_BLOCK"
        return "PII_GUARDRAIL_SANITIZE"

    # Toxicity guardrail - second guardrail priority
    if toxicity_guardrail_triggered:
        tox_bt = toxicity_block_threshold if toxicity_block_threshold is not None else block_threshold
        if toxicity_score >= tox_bt:
            return "TOXICITY_GUARDRAIL_BLOCK"
        return "TOXICITY_GUARDRAIL_SANITIZE"

    # Dominant detection layer
    scores = {
        "RULE_DETECTOR": rule_score,
        "ML_DETECTOR":   ml_score,
        "LLM_DETECTOR":  llm_score,
    }

    max_score = max(scores.values())
    if max_score <= 0.0:
        return "NO_THREAT_DETECTED"

    return max(scores, key=scores.get)