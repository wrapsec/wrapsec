import logging
from dataclasses import dataclass
from engine.guardrails.pii.detector import PIIDetector
from engine.guardrails.pii.redactor import PIIRedactor
from engine.detection.base import DetectionResult

logger = logging.getLogger("wrapsec.engine")


@dataclass
class InputGuardResult:
    text:            str
    sanitized_text:  str | None
    pii_result:      DetectionResult
    redacted_types:  list[str]
    was_sanitized:   bool


class InputGuard:
    """
    Orchestrates PII detection and redaction on input text.
    Returns the original or sanitised text depending on PII findings.
    """

    def __init__(self):
        self._detector = PIIDetector()
        self._redactor = PIIRedactor()

    def inspect(self, text: str) -> InputGuardResult:
        try:
            pii_result = self._detector.detect(text)

            if not pii_result.triggered:
                return InputGuardResult(
                    text           = text,
                    sanitized_text = None,
                    pii_result     = pii_result,
                    redacted_types = [],
                    was_sanitized  = False,
                )

            sanitized, redacted_types = self._redactor.redact(text)

            return InputGuardResult(
                text           = text,
                sanitized_text = sanitized,
                pii_result     = pii_result,
                redacted_types = redacted_types,
                was_sanitized  = True,
            )

        except Exception as e:
            logger.error(f"InputGuard failed: {e}")
            return InputGuardResult(
                text           = text,
                sanitized_text = None,
                pii_result     = DetectionResult.clean("input_guard"),
                redacted_types = [],
                was_sanitized  = False,
            )