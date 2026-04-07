import pytest
from engine.scoring.risk_scorer import RiskScorer
from engine.detection.base import DetectionResult
from domain.enums import ThreatCategory


@pytest.fixture
def scorer():
    return RiskScorer()


def test_all_clean_returns_zero(scorer):
    result = scorer.score(
        DetectionResult.clean("rule"),
        DetectionResult.clean("ml"),
        DetectionResult.clean("llm"),
        DetectionResult.clean("pii"),
    )
    assert result.final_score.value == 0.0
    assert result.boosted is False
    assert result.threats == []


def test_strong_rule_score_boosts(scorer):
    result = scorer.score(
        DetectionResult(0.85, [ThreatCategory.PROMPT_INJECTION], True, "rule"),
        DetectionResult.clean("ml"),
        DetectionResult.clean("llm"),
        DetectionResult.clean("pii"),
    )
    assert result.final_score.value == 0.85
    assert result.boosted is True


def test_threats_aggregated_from_all_layers(scorer):
    result = scorer.score(
        DetectionResult(0.85, [ThreatCategory.PROMPT_INJECTION], True, "rule"),
        DetectionResult(0.30, [ThreatCategory.JAILBREAK], True, "ml"),
        DetectionResult.clean("llm"),
        DetectionResult(0.65, [ThreatCategory.PII], True, "pii"),
    )
    assert ThreatCategory.PROMPT_INJECTION in result.threats
    assert ThreatCategory.JAILBREAK in result.threats
    assert ThreatCategory.PII in result.threats


def test_benign_not_in_threats(scorer):
    result = scorer.score(
        DetectionResult.clean("rule"),
        DetectionResult.clean("ml"),
        DetectionResult.clean("llm"),
        DetectionResult.clean("pii"),
    )
    assert ThreatCategory.BENIGN not in result.threats


def test_score_clamped_at_one(scorer):
    result = scorer.score(
        DetectionResult(1.0, [ThreatCategory.PROMPT_INJECTION], True, "rule"),
        DetectionResult(1.0, [ThreatCategory.JAILBREAK], True, "ml"),
        DetectionResult(1.0, [ThreatCategory.MALICIOUS_INTENT], True, "llm"),
        DetectionResult(1.0, [ThreatCategory.PII], True, "pii"),
    )
    assert result.final_score.value <= 1.0


def test_duplicate_threats_deduplicated(scorer):
    result = scorer.score(
        DetectionResult(0.85, [ThreatCategory.PROMPT_INJECTION], True, "rule"),
        DetectionResult(0.30, [ThreatCategory.PROMPT_INJECTION], True, "ml"),
        DetectionResult.clean("llm"),
        DetectionResult.clean("pii"),
    )
    assert result.threats.count(ThreatCategory.PROMPT_INJECTION) == 1