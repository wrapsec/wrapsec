import logging
from dataclasses import dataclass
from engine.detection.base import DetectionResult
from domain.enums import ThreatCategory
from domain.value_objects.risk_score import RiskScore

logger = logging.getLogger("wrapsec.engine")


@dataclass
class ScoringResult:
    final_score:  RiskScore
    rule_score:   float
    ml_score:     float
    llm_score:    float
    pii_score:    float
    threats:      list[ThreatCategory]
    boosted:      bool = False


class RiskScorer:
    """
    Aggregates detection scores from all layers into a unified risk score.

    Weighting:
      - LLM score carries highest weight (most accurate but conditional)
      - Rule score carries high weight (deterministic, fast)
      - ML score carries medium weight (probabilistic)
      - PII score carries lower weight (always sanitize, not block)

    Boost mechanism:
      If any single detector fires strongly (>= boost_threshold),
      the final score is floored at that value — preventing a strong
      signal from being diluted by lower scores on other layers.
    """

    # Layer weights — must sum to 1.0
    WEIGHT_RULE = 0.35
    WEIGHT_ML   = 0.25
    WEIGHT_LLM  = 0.30
    WEIGHT_PII  = 0.10

    # If any single detector exceeds this, floor the final score at its value
    BOOST_THRESHOLD = 0.5

    def score(
        self,
        rule_result: DetectionResult,
        ml_result:   DetectionResult,
        llm_result:  DetectionResult,
        pii_result:  DetectionResult,
    ) -> ScoringResult:
        try:
            rule_score = rule_result.score
            ml_score   = ml_result.score
            llm_score  = llm_result.score
            pii_score  = pii_result.score

            # Weighted aggregation
            weighted = (
                rule_score * self.WEIGHT_RULE +
                ml_score   * self.WEIGHT_ML   +
                llm_score  * self.WEIGHT_LLM  +
                pii_score  * self.WEIGHT_PII
            )

            # Boost — prevent strong signal from being diluted
            all_scores = [rule_score, ml_score, llm_score, pii_score]
            max_score  = max(all_scores)
            boosted    = False

            if max_score >= self.BOOST_THRESHOLD:
                final = max(weighted, max_score)
                boosted = True
            else:
                final = weighted

            final = round(min(final, 1.0), 4)

            # Aggregate unique threats from all layers
            threats: list[ThreatCategory] = []
            seen = set()
            for result in [rule_result, ml_result, llm_result, pii_result]:
                for threat in result.threats:
                    if threat not in seen and threat != ThreatCategory.BENIGN:
                        threats.append(threat)
                        seen.add(threat)

            return ScoringResult(
                final_score = RiskScore(final),
                rule_score  = rule_score,
                ml_score    = ml_score,
                llm_score   = llm_score,
                pii_score   = pii_score,
                threats     = threats,
                boosted     = boosted,
            )

        except Exception as e:
            logger.error(f"RiskScorer failed: {e}")
            return ScoringResult(
                final_score = RiskScore(0.0),
                rule_score  = 0.0,
                ml_score    = 0.0,
                llm_score   = 0.0,
                pii_score   = 0.0,
                threats     = [],
                boosted     = False,
            )