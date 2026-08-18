# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Transformer-based threat detector -- Tier 2 of the two-tier ML detection pipeline.

Uses protectai/deberta-v3-base-prompt-injection-v2 by default (passed via constructor).
Binary classifier: INJECTION vs SAFE.

Loading:
    Loaded eagerly at startup via DetectionPipeline.__init__.
    Never lazy-loaded on first request -- first-request initialization causes latency spikes.
    If load fails, detector status is set to DEGRADED and detection continues via Tier 1 only.

Timeout:
    Inference timeout is enforced by DetectionPipeline, not here.
    This class is synchronous -- asyncio.to_thread + asyncio.wait_for wrap the detect() call.
"""

import logging

from domain.enums import ThreatCategory
from engine.detection.base import BaseDetector, DetectionResult

logger = logging.getLogger("wrapsec.engine.transformer")

# Confidence threshold below which INJECTION label is treated as SAFE.
# Matches standard binary classification convention.
_CONFIDENCE_THRESHOLD = 0.5

# Label string returned by the HuggingFace pipeline for the injection class.
_INJECTION_LABEL = "INJECTION"


class TransformerDetector(BaseDetector):
    """
    DeBERTa-v3 transformer detector for semantic prompt injection detection.

    Detects injection attacks that evade rule-based and TF-IDF detection through
    paraphrasing or indirect phrasing. Understands context, not just surface patterns.

    The model ID is passed as a constructor argument. It is defined in DetectorProfile
    (profiles.py) and never hardcoded here -- this keeps custom/enterprise model
    substitution contained to the profile registry.
    """

    _class_ready: bool = False

    @classmethod
    def is_model_loaded(cls) -> bool:
        return cls._class_ready

    def __init__(self, model_id: str):
        self._model_id = model_id
        self._pipeline = None
        self._ready    = False
        self._load_model()

    def _load_model(self) -> None:
        try:
            from transformers import pipeline as hf_pipeline  # type: ignore
            self._pipeline             = hf_pipeline(
                "text-classification",
                model     = self._model_id,
                device    = -1,   # CPU -- GPU support: change to device=0
                truncation = True,
                max_length = 512,
            )
            self._ready                    = True
            TransformerDetector._class_ready = True
            logger.info("Transformer model loaded: %s", self._model_id)
        except Exception as e:
            logger.error(
                "Transformer model failed to load -- running in degraded detection mode. "
                "model=%s error=%s",
                self._model_id, e,
            )

    @property
    def name(self) -> str:
        return "transformer_detector"

    @property
    def is_ready(self) -> bool:
        return self._ready

    def detect(self, text: str) -> DetectionResult:
        if not self._ready or self._pipeline is None:
            return DetectionResult.clean(self.name)

        try:
            result     = self._pipeline(text)
            label      = result[0]["label"]
            confidence = float(result[0]["score"])

            if label == _INJECTION_LABEL and confidence >= _CONFIDENCE_THRESHOLD:
                return DetectionResult(
                    score     = round(confidence, 4),
                    threats   = [ThreatCategory.PROMPT_INJECTION],
                    triggered = True,
                    detector  = self.name,
                    details   = {
                        "label":      label,
                        "confidence": round(confidence, 4),
                        "model":      self._model_id,
                    },
                )

            return DetectionResult.clean(self.name)

        except Exception as e:
            logger.warning("TransformerDetector inference failed: %s", e)
            return DetectionResult.clean(self.name)
