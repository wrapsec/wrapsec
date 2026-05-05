# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
from dataclasses import dataclass
from engine.guardrails.pii.detector import PIIDetector
from engine.guardrails.pii.redactor import PIIRedactor
from engine.guardrails.toxicity.detector import ToxicityDetector
from engine.detection.base import DetectionResult

logger = logging.getLogger("wrapsec.engine")


@dataclass
class InputGuardResult:
    text:             str
    sanitized_text:   str | None
    pii_result:       DetectionResult
    toxicity_result:  DetectionResult
    redacted_types:   list[str]
    was_sanitized:    bool


class InputGuard:
    """
    Orchestrates guardrail checks on input text.

    Guardrails (in evaluation order):
      1. PII — detects + redacts sensitive personal data
      2. Toxicity — extracts toxicity signal from ML result

    Note: Toxicity detector is called AFTER ML detection in service.py.
    InputGuard.inspect_toxicity() is called separately with the ML result.
    """

    def __init__(self):
        self._pii_detector = PIIDetector()
        self._pii_redactor = PIIRedactor()
        self._tox_detector = ToxicityDetector()

    def inspect(self, text: str) -> InputGuardResult:
        """Run PII guardrail. Toxicity is added later via inspect_toxicity()."""
        try:
            pii_result = self._pii_detector.detect(text)

            if not pii_result.triggered:
                return InputGuardResult(
                    text            = text,
                    sanitized_text  = None,
                    pii_result      = pii_result,
                    toxicity_result = DetectionResult.clean("toxicity_detector"),
                    redacted_types  = [],
                    was_sanitized   = False,
                )

            sanitized, redacted_types = self._pii_redactor.redact(text)

            return InputGuardResult(
                text            = text,
                sanitized_text  = sanitized,
                pii_result      = pii_result,
                toxicity_result = DetectionResult.clean("toxicity_detector"),
                redacted_types  = redacted_types,
                was_sanitized   = True,
            )

        except Exception as e:
            logger.error(f"InputGuard PII failed: {e}")
            return InputGuardResult(
                text            = text,
                sanitized_text  = None,
                pii_result      = DetectionResult.clean("input_guard"),
                toxicity_result = DetectionResult.clean("toxicity_detector"),
                redacted_types  = [],
                was_sanitized   = False,
            )

    def inspect_toxicity(
        self,
        guard_result: "InputGuardResult",
        ml_result:    DetectionResult,
    ) -> "InputGuardResult":
        """
        Extract toxicity signal from the ML result and attach to guard_result.
        Called after ML detection completes in service.py.
        Returns updated InputGuardResult with toxicity_result populated.
        """
        try:
            toxicity_result = self._tox_detector.detect_from_ml(ml_result)

            return InputGuardResult(
                text            = guard_result.text,
                sanitized_text  = guard_result.sanitized_text,
                pii_result      = guard_result.pii_result,
                toxicity_result = toxicity_result,
                redacted_types  = guard_result.redacted_types,
                was_sanitized   = guard_result.was_sanitized,
            )
        except Exception as e:
            logger.error(f"InputGuard toxicity failed: {e}")
            return guard_result  # Return unchanged — fail open