import re
import logging
from engine.guardrails.pii.detector import _COMPILED_PII

logger = logging.getLogger("wrapsec.engine")

# Redaction masks per PII type
REDACTION_MASKS = {
    "SSN":              "[SSN REDACTED]",
    "SSN_RAW":          "[SSN REDACTED]",
    "PASSPORT":         "[PASSPORT REDACTED]",
    "DRIVERS_LICENSE":  "[DL REDACTED]",
    "CREDIT_CARD":      "[CARD REDACTED]",
    "CREDIT_CARD_LABEL":"[CARD REDACTED]",
    "BANK_ACCOUNT":     "[ACCOUNT REDACTED]",
    "ROUTING_NUMBER":   "[ROUTING REDACTED]",
    "IBAN":             "[IBAN REDACTED]",
    "EMAIL":            "[EMAIL REDACTED]",
    "PHONE":            "[PHONE REDACTED]",
    "DOB":              "[DOB REDACTED]",
    "MEDICAL_RECORD":   "[MEDICAL REDACTED]",
    "MEDICAL_INFO":     "[MEDICAL REDACTED]",
    "PASSWORD":         "[PASSWORD REDACTED]",
    "API_KEY":          "[API KEY REDACTED]",
    "SECRET_KEY":       "[SECRET REDACTED]",
    "STRIPE_KEY":       "[KEY REDACTED]",
    "GITHUB_TOKEN":     "[TOKEN REDACTED]",
    "AWS_KEY":          "[AWS KEY REDACTED]",
    "ZIP_CODE":         "[ZIP REDACTED]",
    "ADDRESS":          "[ADDRESS REDACTED]",
}


class PIIRedactor:
    """
    Redacts PII from text by replacing matches with type-specific masks.
    Stateless — returns a new sanitised string, never modifies in place.
    """

    def redact(self, text: str) -> tuple[str, list[str]]:
        """
        Redact PII from text.
        Returns (redacted_text, list_of_redacted_types).
        """
        try:
            redacted       = text
            redacted_types = []

            for pattern, label in _COMPILED_PII:
                mask = REDACTION_MASKS.get(label, "[REDACTED]")
                new_text, count = pattern.subn(mask, redacted)
                if count > 0:
                    redacted = new_text
                    if label not in redacted_types:
                        redacted_types.append(label)

            return redacted, redacted_types

        except Exception as e:
            logger.error(f"PIIRedactor failed: {e}")
            return text, []