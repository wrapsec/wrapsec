"""
Toxicity guardrail detector.
engine/guardrails/toxicity/detector.py

Extracts the toxicity score from the ML detector result.
The ML model (TF-IDF + LogReg) is trained on:
  - Jigsaw Toxic Comment Classification (Wikipedia CC0, WWW 2017)
  - UC Berkeley Measuring Hate Speech (ACL 2022)
  - ToxiGen — Microsoft Research (ACL 2022)
Label 6 = TOXICITY in the ML classifier.

This guardrail operates independently of the detection risk score.
It reads the ML toxicity confidence directly and applies its own threshold
via the PolicyEngine — same pattern as PIIDetector.

Why a guardrail and not just detection:
  ML toxicity score is weighted at 0.30 in the risk scorer.
  A 0.9 confident toxicity detection produces risk_score = 0.27 — below
  the default sanitize threshold of 0.4 — and would be ALLOWED.
  The guardrail bypasses this dilution by reading the raw ML confidence.

Categories covered by the training data:
  - Hate speech (identity-based attacks)
  - Violent threats
  - Severe profanity and insults
  - Identity attacks (gender, race, religion)
  - Implicit toxicity (ToxiGen)
"""

from engine.detection.base import DetectionResult
from domain.enums import ThreatCategory


class ToxicityDetector:
    """
    Extracts toxicity score from the ML detector result.
    Stateless — reads from existing ML result, no additional inference.
    Fast: ~0ms (no new computation, just score extraction).
    """

    # Score boundaries — same scale as PII detector
    MIN_SCORE = 0.0
    MAX_SCORE = 1.0

    @property
    def name(self) -> str:
        return "toxicity_detector"

    def score_from_ml(self, ml_result: DetectionResult) -> float:
        """
        Extract toxicity confidence from the ML detector result.
        Returns 0.0 if ML did not detect toxicity.

        The ML detector returns ThreatCategory.TOXICITY when label 6 fires.
        We read the raw score (ML confidence) not the weighted risk_score.
        """
        if not ml_result.triggered:
            return 0.0

        if ThreatCategory.TOXICITY not in ml_result.threats:
            return 0.0

        return round(min(ml_result.score, self.MAX_SCORE), 4)

    def detect_from_ml(self, ml_result: DetectionResult) -> DetectionResult:
        """
        Build a DetectionResult from the ML toxicity signal.
        Used by InputGuard to pass toxicity_score to the pipeline.
        """
        score = self.score_from_ml(ml_result)

        if score <= 0.0:
            return DetectionResult.clean(self.name)

        return DetectionResult(
            score     = score,
            threats   = [ThreatCategory.TOXICITY],
            triggered = True,
            detector  = self.name,
            details   = {"source": "ml_detector", "ml_confidence": score},
        )
