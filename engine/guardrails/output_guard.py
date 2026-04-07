import logging
from dataclasses import dataclass
from engine.guardrails.pii.detector import PIIDetector
from engine.guardrails.pii.redactor import PIIRedactor

logger = logging.getLogger("wrapsec.engine")


@dataclass
class OutputGuardResult:
    text:           str
    sanitized_text: str | None
    was_sanitized:  bool
    redacted_types: list[str]


class OutputGuard:
    """
    Checks LLM output for PII and toxicity before returning to client.
    Redacts any PII found in the output.
    Internal only — never exposed via API.
    """

    def __init__(self):
        self._detector = PIIDetector()
        self._redactor = PIIRedactor()

    def inspect(self, text: str) -> OutputGuardResult:
        if not text:
            return OutputGuardResult(
                text           = text,
                sanitized_text = None,
                was_sanitized  = False,
                redacted_types = [],
            )

        try:
            pii_result = self._detector.detect(text)

            if not pii_result.triggered:
                return OutputGuardResult(
                    text           = text,
                    sanitized_text = None,
                    was_sanitized  = False,
                    redacted_types = [],
                )

            sanitized, redacted_types = self._redactor.redact(text)

            logger.warning(
                f"OutputGuard redacted PII from LLM output: {redacted_types}"
            )

            return OutputGuardResult(
                text           = text,
                sanitized_text = sanitized,
                was_sanitized  = True,
                redacted_types = redacted_types,
            )

        except Exception as e:
            logger.error(f"OutputGuard failed: {e}")
            return OutputGuardResult(
                text           = text,
                sanitized_text = None,
                was_sanitized  = False,
                redacted_types = [],
            )