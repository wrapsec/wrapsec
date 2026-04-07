import os
import pickle
import logging
from pathlib import Path
from engine.detection.base import BaseDetector, DetectionResult
from domain.enums import ThreatCategory

logger = logging.getLogger("wrapsec.engine")

# Label mapping from training
LABEL_MAP = {
    0: ThreatCategory.BENIGN,
    1: ThreatCategory.PROMPT_INJECTION,
    2: ThreatCategory.JAILBREAK,
    3: ThreatCategory.MALICIOUS_INTENT,
    4: ThreatCategory.DATA_EXFILTRATION,
    5: ThreatCategory.PII,
    6: ThreatCategory.TOXICITY,
}

MODEL_PATH = Path("models/ml_detector.pkl")


class MLDetector(BaseDetector):
    """
    ML-based threat classifier using TF-IDF + LogisticRegression.
    Migrated from ai-security-gateway prototype.
    Falls back to clean result if model not found.
    """

    def __init__(self):
        self._model    = None
        self._ready    = False
        self._load_model()

    def _load_model(self) -> None:
        if not MODEL_PATH.exists():
            logger.warning(
                f"ML model not found at {MODEL_PATH}. "
                "MLDetector will return clean results until model is trained."
            )
            return
        try:
            with open(MODEL_PATH, "rb") as f:
                self._model = pickle.load(f)
            self._ready = True
            logger.info(f"ML model loaded from {MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")

    @property
    def name(self) -> str:
        return "ml_detector"

    @property
    def is_ready(self) -> bool:
        return self._ready

    def detect(self, text: str) -> DetectionResult:
        if not self._ready or self._model is None:
            return DetectionResult.clean(self.name)

        try:
            proba      = self._model.predict_proba([text])[0]
            class_idx  = int(proba.argmax())
            confidence = float(proba[class_idx])
            category   = LABEL_MAP.get(class_idx, ThreatCategory.BENIGN)

            if category == ThreatCategory.BENIGN or confidence < 0.25:
                return DetectionResult.clean(self.name)

            return DetectionResult(
                score     = round(confidence, 4),
                threats   = [category],
                triggered = True,
                detector  = self.name,
                details   = {
                    "predicted_class": category.value,
                    "confidence":      round(confidence, 4),
                },
            )

        except Exception as e:
            logger.warning(f"MLDetector inference failed: {e}")
            return DetectionResult.clean(self.name)