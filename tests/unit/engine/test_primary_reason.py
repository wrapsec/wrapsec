# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from engine.scoring.primary_reason import compute_primary_reason


def test_pii_block():
    result = compute_primary_reason(
        guardrail_triggered = True,
        guardrail_decision  = "BLOCK",
        rule_score  = 0.0,
        ml_score    = 0.0,
        llm_score   = 0.0,
        pii_score   = 0.73,
        block_threshold    = 0.7,
        sanitize_threshold = 0.4,
    )
    assert result == "PII_GUARDRAIL_BLOCK"


def test_pii_sanitize():
    result = compute_primary_reason(
        guardrail_triggered = True,
        guardrail_decision  = "SANITIZE",
        rule_score  = 0.0,
        ml_score    = 0.0,
        llm_score   = 0.0,
        pii_score   = 0.55,
        block_threshold    = 0.7,
        sanitize_threshold = 0.4,
    )
    assert result == "PII_GUARDRAIL_SANITIZE"


def test_rule_detector_dominant():
    result = compute_primary_reason(
        guardrail_triggered = False,
        guardrail_decision  = None,
        rule_score  = 0.85,
        ml_score    = 0.30,
        llm_score   = 0.00,
        pii_score   = 0.0,
        block_threshold    = 0.7,
        sanitize_threshold = 0.4,
    )
    assert result == "RULE_DETECTOR"


def test_ml_detector_dominant():
    result = compute_primary_reason(
        guardrail_triggered = False,
        guardrail_decision  = None,
        rule_score  = 0.10,
        ml_score    = 0.65,
        llm_score   = 0.20,
        pii_score   = 0.0,
        block_threshold    = 0.7,
        sanitize_threshold = 0.4,
    )
    assert result == "ML_DETECTOR"


def test_llm_detector_dominant():
    result = compute_primary_reason(
        guardrail_triggered = False,
        guardrail_decision  = None,
        rule_score  = 0.10,
        ml_score    = 0.20,
        llm_score   = 0.85,
        pii_score   = 0.0,
        block_threshold    = 0.7,
        sanitize_threshold = 0.4,
    )
    assert result == "LLM_DETECTOR"


def test_no_threat_detected():
    result = compute_primary_reason(
        guardrail_triggered = False,
        guardrail_decision  = None,
        rule_score  = 0.0,
        ml_score    = 0.0,
        llm_score   = 0.0,
        pii_score   = 0.0,
        block_threshold    = 0.7,
        sanitize_threshold = 0.4,
    )
    assert result == "NO_THREAT_DETECTED"


def test_guardrail_takes_priority_over_detectors():
    result = compute_primary_reason(
        guardrail_triggered = True,
        guardrail_decision  = "BLOCK",
        rule_score  = 0.85,
        ml_score    = 0.75,
        llm_score   = 0.90,
        pii_score   = 0.73,
        block_threshold    = 0.7,
        sanitize_threshold = 0.4,
    )
    assert result == "PII_GUARDRAIL_BLOCK"


# ── v1.0.9: toxicity is BLOCK-or-ALLOW only (Bedrock semantics) ─

def test_toxicity_guardrail_returns_block_only():
    """
    Toxicity guardrail triggered must always map to TOXICITY_GUARDRAIL_BLOCK.
    v1.0.9 removed the SANITIZE tier - even scores below what used to be the
    sanitize threshold must not produce TOXICITY_GUARDRAIL_SANITIZE.
    """
    result = compute_primary_reason(
        guardrail_triggered          = False,
        guardrail_decision           = None,
        rule_score                   = 0.0,
        ml_score                     = 0.0,
        llm_score                    = 0.0,
        pii_score                    = 0.0,
        block_threshold              = 0.7,
        sanitize_threshold           = 0.4,
        toxicity_score               = 0.55,   # below old sanitize threshold
        toxicity_guardrail_triggered = True,
        toxicity_block_threshold     = 0.5,
    )
    assert result == "TOXICITY_GUARDRAIL_BLOCK"


def test_toxicity_never_returns_sanitize_variant():
    """
    Explicit ban on the removed TOXICITY_GUARDRAIL_SANITIZE literal - even for
    a low toxicity score, the mapper must return BLOCK (the caller controls
    whether the guardrail fired at all via toxicity_guardrail_triggered).
    """
    result = compute_primary_reason(
        guardrail_triggered          = False,
        guardrail_decision           = None,
        rule_score                   = 0.0,
        ml_score                     = 0.0,
        llm_score                    = 0.0,
        pii_score                    = 0.0,
        toxicity_score               = 0.3,
        toxicity_guardrail_triggered = True,
        toxicity_block_threshold     = 0.7,
    )
    assert result != "TOXICITY_GUARDRAIL_SANITIZE"
    assert result == "TOXICITY_GUARDRAIL_BLOCK"