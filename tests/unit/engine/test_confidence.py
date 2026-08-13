# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from engine.scoring.confidence import (
    compute_confidence,
    detector_confidence,
    get_confidence_band,
    guardrail_confidence,
)

# ── detector_confidence ────────────────────────────────────────

def test_single_layer_returns_1():
    result = detector_confidence(
        rule_score=0.85, ml_score=0.0, llm_score=0.0,
        rule_enabled=True, ml_enabled=False, llm_invoked=False,
    )
    assert result == 1.0


def test_all_layers_agree_high_confidence():
    result = detector_confidence(
        rule_score=0.85, ml_score=0.80, llm_score=0.90,
        rule_enabled=True, ml_enabled=True, llm_invoked=True,
    )
    assert result >= 0.9


def test_layers_disagree_medium_confidence():
    result = detector_confidence(
        rule_score=0.85, ml_score=0.10, llm_score=0.15,
        rule_enabled=True, ml_enabled=True, llm_invoked=True,
    )
    assert result < 0.8


def test_llm_not_invoked_excluded_from_variance():
    # LLM not invoked - only rule + ml
    result_without_llm = detector_confidence(
        rule_score=0.85, ml_score=0.30, llm_score=0.0,
        rule_enabled=True, ml_enabled=True, llm_invoked=False,
    )
    # LLM invoked with 0.0 score - inflates variance
    result_with_llm_zero = detector_confidence(
        rule_score=0.85, ml_score=0.30, llm_score=0.0,
        rule_enabled=True, ml_enabled=True, llm_invoked=True,
    )
    # Excluding uninvoked LLM gives higher confidence
    assert result_without_llm >= result_with_llm_zero


def test_confidence_floor_for_strong_signal():
    # Strong rule signal should have at least 0.75 confidence
    result = detector_confidence(
        rule_score=0.85, ml_score=0.05, llm_score=0.10,
        rule_enabled=True, ml_enabled=True, llm_invoked=True,
    )
    assert result >= 0.75


def test_zero_scores_returns_1():
    result = detector_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        rule_enabled=True, ml_enabled=True, llm_invoked=False,
    )
    assert result == 1.0


# ── guardrail_confidence ───────────────────────────────────────

def test_pii_block_level_high_confidence():
    result = guardrail_confidence(
        pii_score=0.73, block_threshold=0.7, sanitize_threshold=0.4
    )
    assert 0.90 <= result <= 0.95


def test_pii_sanitize_level_medium_high_confidence():
    result = guardrail_confidence(
        pii_score=0.55, block_threshold=0.7, sanitize_threshold=0.4
    )
    assert 0.70 <= result <= 0.84


def test_pii_below_sanitize_returns_zero():
    result = guardrail_confidence(
        pii_score=0.2, block_threshold=0.7, sanitize_threshold=0.4
    )
    assert result == 0.0


def test_pii_at_block_threshold_exactly():
    result = guardrail_confidence(
        pii_score=0.7, block_threshold=0.7, sanitize_threshold=0.4
    )
    assert result == 0.90


def test_pii_max_score_capped_at_095():
    result = guardrail_confidence(
        pii_score=1.0, block_threshold=0.7, sanitize_threshold=0.4
    )
    assert result <= 0.95


# ── compute_confidence ─────────────────────────────────────────

def test_pii_guardrail_triggered_uses_guardrail_confidence():
    confidence, band = compute_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        pii_score=0.73,
        pii_guardrail_triggered=True,
        block_threshold=0.7, sanitize_threshold=0.4,
    )
    assert confidence >= 0.90
    assert band == "HIGH"


def test_no_guardrail_uses_detector_confidence():
    _confidence, band = compute_confidence(
        rule_score=0.85, ml_score=0.80, llm_score=0.0,
        pii_score=0.0,
        pii_guardrail_triggered=False,
        rule_enabled=True, ml_enabled=True, llm_invoked=False,
    )
    assert band == "HIGH"


def test_confidence_capped_at_1():
    confidence, _ = compute_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        pii_score=0.0,
        pii_guardrail_triggered=False,
    )
    assert confidence <= 1.0


# ── F-2 regression + v1.0.9 BLOCK-only tier ────────────────────
# Historical F-2 bug: service.py passed the combined PII-or-toxicity flag as
# the first parameter, and compute_confidence branch 1 used pii_score. A
# toxicity-only decision ended up with confidence 0.0 / LOW because
# pii_score was 0.0.
#
# v1.0.9: toxicity SANITIZE tier removed (Bedrock-style BLOCK-or-ALLOW). The
# toxicity_sanitize_threshold parameter is retained for signature compatibility
# but is a no-op. Toxicity guardrail can only produce a BLOCK-tier confidence.

def test_toxicity_only_decision_produces_high_confidence():
    """
    pii_guardrail_triggered=False + toxicity_guardrail_triggered=True must
    route into the toxicity branch and produce BLOCK-tier confidence from
    toxicity_score (not fall through to pii_score=0.0 in branch 1).
    """
    confidence, band = compute_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        pii_score=0.0,
        pii_guardrail_triggered=False,
        toxicity_score=0.85,
        toxicity_guardrail_triggered=True,
        toxicity_block_threshold=0.7,
    )
    assert confidence >= 0.90
    assert band == "HIGH"


def test_toxicity_branch_uses_toxicity_thresholds_not_detection_thresholds():
    """
    Toxicity branch must tier against its own block threshold so the band
    matches the guardrail that fired, ignoring the detection thresholds.
    """
    confidence, band = compute_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        pii_score=0.0,
        pii_guardrail_triggered=False,
        block_threshold=0.95,     # detection threshold - must be ignored
        sanitize_threshold=0.80,  # detection threshold - must be ignored
        toxicity_score=0.5,
        toxicity_guardrail_triggered=True,
        toxicity_block_threshold=0.5,
    )
    # 0.5 >= tox_block_threshold (0.5) -> BLOCK tier -> confidence >= 0.90
    assert confidence >= 0.90
    assert band == "HIGH"


def test_toxicity_sanitize_threshold_param_is_deprecated_noop():
    """
    v1.0.9: the toxicity_sanitize_threshold parameter is retained for signature
    compatibility but must not affect confidence. Passing an extreme value must
    produce the same confidence as omitting it entirely.
    """
    base_confidence, _ = compute_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        pii_score=0.0,
        pii_guardrail_triggered=False,
        toxicity_score=0.85,
        toxicity_guardrail_triggered=True,
        toxicity_block_threshold=0.7,
    )
    with_noop_arg, _ = compute_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        pii_score=0.0,
        pii_guardrail_triggered=False,
        toxicity_score=0.85,
        toxicity_guardrail_triggered=True,
        toxicity_block_threshold=0.7,
        toxicity_sanitize_threshold=0.0001,  # extreme value; must be ignored
    )
    assert with_noop_arg == base_confidence


def test_pii_triggered_still_takes_priority_over_toxicity():
    """PII branch wins if both guardrails fire (order: PII then toxicity)."""
    _confidence, band = compute_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        pii_score=0.9,
        pii_guardrail_triggered=True,
        block_threshold=0.7, sanitize_threshold=0.4,
        toxicity_score=0.6,
        toxicity_guardrail_triggered=True,
        toxicity_block_threshold=0.5,
    )
    # PII branch used - confidence derived from pii_score, not toxicity_score
    assert band == "HIGH"


# ── get_confidence_band ────────────────────────────────────────

def test_band_high():
    assert get_confidence_band(0.95) == "HIGH"
    assert get_confidence_band(0.70) == "HIGH"


def test_band_medium():
    assert get_confidence_band(0.65) == "MEDIUM"
    assert get_confidence_band(0.40) == "MEDIUM"


def test_band_low():
    assert get_confidence_band(0.39) == "LOW"
    assert get_confidence_band(0.0)  == "LOW"