# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
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

_REPO_ROOT      = Path(__file__).resolve().parent.parent.parent
MODEL_PATH      = _REPO_ROOT / "models" / "ml_detector.pkl"
MODEL_HASH_PATH = _REPO_ROOT / "models" / "ml_detector.pkl.sha256"


class MLDetector(BaseDetector):
    """
    ML-based threat classifier using TF-IDF + LogisticRegression.
    Migrated from ai-security-gateway prototype.
    Falls back to clean result if model not found.
    """

    _class_ready: bool = False  # set to True when any instance loads the model

    @classmethod
    def is_model_loaded(cls) -> bool:
        return cls._class_ready

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
            raw = MODEL_PATH.read_bytes()

            # Integrity check — refuse to unpickle if hash file exists and mismatches.
            # pickle.load() executes arbitrary code; a tampered model is an RCE vector.
            if MODEL_HASH_PATH.exists():
                expected = MODEL_HASH_PATH.read_text().strip().lower()
                actual   = hashlib.sha256(raw).hexdigest().lower()
                if actual != expected:
                    logger.error(
                        "ML model integrity check FAILED — "
                        "expected=%s actual=%s path=%s — refusing to load",
                        expected[:16] + "...", actual[:16] + "...", MODEL_PATH,
                    )
                    return
            else:
                logger.warning(
                    "No integrity file at %s — ML model loaded WITHOUT hash verification. "
                    "Generate it with: sha256sum %s > %s",
                    MODEL_HASH_PATH, MODEL_PATH, MODEL_HASH_PATH,
                )

            self._model             = pickle.loads(raw)
            self._ready             = True
            MLDetector._class_ready = True
            logger.info("ML model loaded from %s", MODEL_PATH)
        except Exception as e:
            logger.error("Failed to load ML model: %s", e)

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