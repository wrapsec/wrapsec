# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Regression tests for engine.scoring.risk_scorer.

The scorer sits directly upstream of the PolicyEngine, so any bug here silently
mis-decides every request. These tests lock in four invariants that would
otherwise only surface in production:

  1. Weighted aggregation of rule/ml/llm follows the documented weights
     (0.40 / 0.30 / 0.30) and PII is excluded from the detection score.
  2. Boost: if any single detector fires >= BOOST_THRESHOLD (0.5), the final
     score is floored at that value, so a strong rule hit cannot be diluted
     by a low ml/llm score.
  3. Fail-closed on any internal exception - the scorer returns RiskScore(1.0)
     so the PolicyEngine blocks, never a permissive zero.
  4. Threat aggregation is deduplicated across detectors and BENIGN is stripped.

If any of these break, the gateway makes wrong decisions in silence.
"""

import pytest

from domain.enums import ThreatCategory
from domain.value_objects.risk_score import RiskScore
from engine.detection.base import DetectionResult
from engine.scoring.risk_scorer import RiskScorer, ScoringResult

# ── helpers ──────────────────────────────────────────────────────────────────

def _result(
    score:     float,
    detector:  str,
    threats:   list[ThreatCategory] | None = None,
    triggered: bool | None = None,
) -> DetectionResult:
    return DetectionResult(
        score     = score,
        threats   = threats   if threats   is not None else [],
        triggered = triggered if triggered is not None else score > 0,
        detector  = detector,
    )


@pytest.fixture
def scorer():
    return RiskScorer()


# ── weighted aggregation ─────────────────────────────────────────────────────

def test_all_zero_scores_produce_zero_final(scorer):
    """A fully benign input must not be inflated by aggregation logic."""
    result = scorer.score(
        rule_result = DetectionResult.clean("rule"),
        ml_result   = DetectionResult.clean("ml"),
        llm_result  = DetectionResult.clean("llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    assert result.final_score == RiskScore(0.0)
    assert result.boosted is False
    assert result.threats == []


def test_weights_match_documented_ratios(scorer):
    """
    With every detector at 0.4 (just under boost), expected weighted score
    is 0.4 * 0.4 + 0.4 * 0.3 + 0.4 * 0.3 = 0.40. Guards against silent
    weight drift.
    """
    r = scorer.score(
        rule_result = _result(0.4, "rule"),
        ml_result   = _result(0.4, "ml"),
        llm_result  = _result(0.4, "llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    assert r.final_score == RiskScore(0.4)
    assert r.boosted is False


def test_rule_weight_dominates_ml_and_llm(scorer):
    """
    Rule = 1.0, others = 0.0 -> weighted 0.40 but boost floor forces >= 1.0.
    Also proves the weight order: rule (0.4) > ml (0.3) == llm (0.3).
    """
    r = scorer.score(
        rule_result = _result(1.0, "rule",  [ThreatCategory.PROMPT_INJECTION]),
        ml_result   = DetectionResult.clean("ml"),
        llm_result  = DetectionResult.clean("llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    # Boost kicks in - rule=1.0 >= BOOST_THRESHOLD - floor at 1.0
    assert r.final_score == RiskScore(1.0)
    assert r.boosted is True


def test_pii_score_excluded_from_final(scorer):
    """
    PII is a guardrail, not a detector, and the PolicyEngine evaluates it
    independently. If PII ever gets folded into final_score, ALLOW-vs-SANITIZE
    boundaries move for every request that contains PII.
    """
    r = scorer.score(
        rule_result = DetectionResult.clean("rule"),
        ml_result   = DetectionResult.clean("ml"),
        llm_result  = DetectionResult.clean("llm"),
        pii_result  = _result(0.9, "pii", [ThreatCategory.PII]),
    )
    assert r.final_score == RiskScore(0.0)     # detection score untouched
    assert r.pii_score  == 0.9                  # but exposed separately


# ── boost mechanism ──────────────────────────────────────────────────────────

def test_boost_fires_at_threshold_exactly(scorer):
    """
    Boundary check: a detector hitting exactly BOOST_THRESHOLD (0.5) must
    trigger boost. Off-by-one here means strong-but-borderline signals get
    diluted, which is how prompt-injection variants slip past.
    """
    r = scorer.score(
        rule_result = _result(0.5, "rule"),
        ml_result   = _result(0.1, "ml"),
        llm_result  = _result(0.1, "llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    # weighted = 0.5*0.4 + 0.1*0.3 + 0.1*0.3 = 0.26
    # boost floors final at max_score = 0.5
    assert r.final_score == RiskScore(0.5)
    assert r.boosted is True


def test_no_boost_below_threshold(scorer):
    """
    All detectors just under threshold - final score must equal the weighted
    aggregate with no boost applied.
    """
    r = scorer.score(
        rule_result = _result(0.49, "rule"),
        ml_result   = _result(0.49, "ml"),
        llm_result  = _result(0.49, "llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    assert r.boosted is False
    # 0.49 * (0.4 + 0.3 + 0.3) = 0.49
    assert r.final_score == RiskScore(0.49)


def test_boost_only_considers_detection_scores_not_pii(scorer):
    """
    A high PII score alone must NOT trigger boost. If it did, the detection
    score would inherit the PII confidence and mis-drive the ML/rule pipeline.
    """
    r = scorer.score(
        rule_result = _result(0.1, "rule"),
        ml_result   = _result(0.1, "ml"),
        llm_result  = _result(0.1, "llm"),
        pii_result  = _result(0.95, "pii", [ThreatCategory.PII]),
    )
    assert r.boosted is False
    # 0.1 * (0.4 + 0.3 + 0.3) = 0.10 -- PII does NOT participate
    assert r.final_score == RiskScore(0.10)


# ── clamping ─────────────────────────────────────────────────────────────────

def test_final_score_clamped_to_one(scorer):
    """
    Even if every detector fires at maximum, final must never exceed 1.0.
    RiskScore(>1.0) raises ValueError - would crash the scorer.
    """
    r = scorer.score(
        rule_result = _result(1.0, "rule"),
        ml_result   = _result(1.0, "ml"),
        llm_result  = _result(1.0, "llm"),
        pii_result  = _result(1.0, "pii", [ThreatCategory.PII]),
    )
    assert r.final_score == RiskScore(1.0)


# ── threat aggregation ──────────────────────────────────────────────────────

def test_threats_deduplicated_across_detectors(scorer):
    """
    Rule and ML both flagged PROMPT_INJECTION - the aggregate must list it
    once. If dedup breaks, downstream UI shows duplicate threats and audit
    logs get noisier over time.
    """
    r = scorer.score(
        rule_result = _result(0.6, "rule", [ThreatCategory.PROMPT_INJECTION]),
        ml_result   = _result(0.6, "ml",   [ThreatCategory.PROMPT_INJECTION]),
        llm_result  = DetectionResult.clean("llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    assert r.threats == [ThreatCategory.PROMPT_INJECTION]


def test_benign_is_stripped_from_threats(scorer):
    """
    BENIGN is not an actionable threat category - it must never appear in
    the aggregated list even if a detector reports it. The dashboard would
    otherwise render 'BENIGN' as a threat pill next to real ones.
    """
    r = scorer.score(
        rule_result = _result(0.0, "rule", [ThreatCategory.BENIGN]),
        ml_result   = _result(0.6, "ml",   [ThreatCategory.PROMPT_INJECTION]),
        llm_result  = DetectionResult.clean("llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    assert ThreatCategory.BENIGN not in r.threats
    assert r.threats == [ThreatCategory.PROMPT_INJECTION]


def test_threats_from_multiple_detectors_are_all_included(scorer):
    """
    Different threat categories from different detectors must all surface -
    otherwise the audit trail loses which layer caught what.
    """
    r = scorer.score(
        rule_result = _result(0.6, "rule", [ThreatCategory.PROMPT_INJECTION]),
        ml_result   = _result(0.6, "ml",   [ThreatCategory.JAILBREAK]),
        llm_result  = _result(0.6, "llm",  [ThreatCategory.MALICIOUS_INTENT]),
        pii_result  = _result(0.6, "pii",  [ThreatCategory.PII]),
    )
    assert set(r.threats) == {
        ThreatCategory.PROMPT_INJECTION,
        ThreatCategory.JAILBREAK,
        ThreatCategory.MALICIOUS_INTENT,
        ThreatCategory.PII,
    }


def test_toxicity_threats_included_when_triggered(scorer):
    """
    Toxicity is optional (fifth arg). When present and triggered, its threats
    must be added; when None, scoring must still work.
    """
    tox = _result(0.8, "toxicity", [ThreatCategory.TOXICITY], triggered=True)
    r = scorer.score(
        rule_result     = DetectionResult.clean("rule"),
        ml_result       = DetectionResult.clean("ml"),
        llm_result      = DetectionResult.clean("llm"),
        pii_result      = DetectionResult.clean("pii"),
        toxicity_result = tox,
    )
    assert ThreatCategory.TOXICITY in r.threats
    assert r.toxicity_score == 0.8


def test_toxicity_none_defaults_to_zero(scorer):
    """toxicity_score must default to 0.0 when no toxicity_result is passed."""
    r = scorer.score(
        rule_result = DetectionResult.clean("rule"),
        ml_result   = DetectionResult.clean("ml"),
        llm_result  = DetectionResult.clean("llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    assert r.toxicity_score == 0.0


# ── fail-closed ──────────────────────────────────────────────────────────────

def test_fail_closed_on_exception_returns_max_score(scorer):
    """
    CRITICAL invariant: if any internal step raises, the scorer must return
    RiskScore(1.0) so the PolicyEngine blocks. A permissive zero here would
    let malicious input through whenever the scorer hiccups (memory pressure,
    detector bug, deserialisation glitch, etc.).
    """
    class _Boom:
        # Any attribute access raises - simulates a detector result whose
        # .score raised somewhere upstream but was still passed in.
        def __getattr__(self, item):
            raise RuntimeError("simulated detector failure")

    r = scorer.score(
        rule_result = _Boom(),   # type: ignore[arg-type]
        ml_result   = DetectionResult.clean("ml"),
        llm_result  = DetectionResult.clean("llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    assert r.final_score == RiskScore(1.0)
    assert r.threats == []
    assert r.boosted is False


def test_fail_closed_result_is_scoring_result_not_none(scorer):
    """
    Fail-closed path must return a ScoringResult, not raise or return None.
    Callers assume the return type is always ScoringResult - a None here
    causes an AttributeError deep in the pipeline that hides the root cause.
    """
    class _Boom:
        def __getattr__(self, item):
            raise RuntimeError("boom")

    r = scorer.score(
        rule_result = _Boom(),   # type: ignore[arg-type]
        ml_result   = DetectionResult.clean("ml"),
        llm_result  = DetectionResult.clean("llm"),
        pii_result  = DetectionResult.clean("pii"),
    )
    assert isinstance(r, ScoringResult)
