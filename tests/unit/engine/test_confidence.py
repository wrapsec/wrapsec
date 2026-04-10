import pytest
from engine.scoring.confidence import (
    detector_confidence,
    guardrail_confidence,
    compute_confidence,
    get_confidence_band,
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
    # LLM not invoked — only rule + ml
    result_without_llm = detector_confidence(
        rule_score=0.85, ml_score=0.30, llm_score=0.0,
        rule_enabled=True, ml_enabled=True, llm_invoked=False,
    )
    # LLM invoked with 0.0 score — inflates variance
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

def test_guardrail_triggered_uses_guardrail_confidence():
    confidence, band = compute_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        pii_score=0.73,
        guardrail_triggered=True,
        block_threshold=0.7, sanitize_threshold=0.4,
    )
    assert confidence >= 0.90
    assert band == "HIGH"


def test_no_guardrail_uses_detector_confidence():
    confidence, band = compute_confidence(
        rule_score=0.85, ml_score=0.80, llm_score=0.0,
        pii_score=0.0,
        guardrail_triggered=False,
        rule_enabled=True, ml_enabled=True, llm_invoked=False,
    )
    assert band == "HIGH"


def test_confidence_capped_at_1():
    confidence, _ = compute_confidence(
        rule_score=0.0, ml_score=0.0, llm_score=0.0,
        pii_score=0.0,
        guardrail_triggered=False,
    )
    assert confidence <= 1.0


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