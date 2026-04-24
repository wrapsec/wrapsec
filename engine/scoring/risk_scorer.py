import logging
from dataclasses import dataclass
from engine.detection.base import DetectionResult
from domain.enums import ThreatCategory
from domain.value_objects.risk_score import RiskScore

logger = logging.getLogger("wrapsec.engine")


@dataclass
class ScoringResult:
    final_score:    RiskScore
    rule_score:     float
    ml_score:       float
    llm_score:      float
    pii_score:      float
    toxicity_score: float
    threats:        list[ThreatCategory]
    boosted:        bool = False


class RiskScorer:
    """
    Aggregates detection scores from all layers into a unified risk score.

    Architecture — two separate concerns:

    Detection layers (probabilistic — identify malicious intent):
      rule_score, ml_score, llm_score
      Weighted aggregation → detection_risk_score
      Weights: rule=0.40, ml=0.30, llm=0.30

    Guardrail layers (deterministic — enforce data protection):
      pii_score (and future: toxicity, bias)
      Evaluated independently by the policy engine
      NEVER mixed into the detection risk score

    Boost mechanism:
      If any single detector fires strongly (>= boost_threshold),
      the final detection score is floored at that value.
      Prevents a strong signal from being diluted by lower scores.
    """

    # Detection layer weights — must sum to 1.0
    # PII is excluded — it is a guardrail, not a detector
    WEIGHT_RULE = 0.40
    WEIGHT_ML   = 0.30
    WEIGHT_LLM  = 0.30

    # If any single detector exceeds this, floor the final score at its value
    BOOST_THRESHOLD = 0.5

    def score(
        self,
        rule_result:     DetectionResult,
        ml_result:       DetectionResult,
        llm_result:      DetectionResult,
        pii_result:      DetectionResult,
        toxicity_result: DetectionResult | None = None,
    ) -> ScoringResult:
        try:
            rule_score     = rule_result.score
            ml_score       = ml_result.score
            llm_score      = llm_result.score
            pii_score      = pii_result.score
            toxicity_score = toxicity_result.score if toxicity_result else 0.0

            # Detection risk score — detectors only, no PII
            weighted = (
                rule_score * self.WEIGHT_RULE +
                ml_score   * self.WEIGHT_ML   +
                llm_score  * self.WEIGHT_LLM
            )

            # Boost — prevent strong signal from being diluted
            # Only detection layer scores contribute to boost
            detection_scores = [rule_score, ml_score, llm_score]
            max_score        = max(detection_scores)
            boosted          = False

            if max_score >= self.BOOST_THRESHOLD:
                final   = max(weighted, max_score)
                boosted = True
            else:
                final = weighted

            final = round(min(final, 1.0), 4)

            # Aggregate unique threats from all layers including guardrails
            threats: list[ThreatCategory] = []
            seen = set()
            for result in [rule_result, ml_result, llm_result, pii_result]:
                for threat in result.threats:
                    if threat not in seen and threat != ThreatCategory.BENIGN:
                        threats.append(threat)
                        seen.add(threat)

            # Add toxicity threats if present (not already in list)
            if toxicity_result and toxicity_result.triggered:
                for threat in toxicity_result.threats:
                    if threat not in seen and threat != ThreatCategory.BENIGN:
                        threats.append(threat)
                        seen.add(threat)

            return ScoringResult(
                final_score    = RiskScore(final),
                rule_score     = rule_score,
                ml_score       = ml_score,
                llm_score      = llm_score,
                pii_score      = pii_score,
                toxicity_score = toxicity_score,
                threats        = threats,
                boosted        = boosted,
            )

        except Exception as e:
            logger.error(f"RiskScorer failed: {e}")
            return ScoringResult(
                final_score    = RiskScore(0.0),
                rule_score     = 0.0,
                ml_score       = 0.0,
                llm_score      = 0.0,
                pii_score      = 0.0,
                toxicity_score = 0.0,
                threats        = [],
                boosted        = False,
            )