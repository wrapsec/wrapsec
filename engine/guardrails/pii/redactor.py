# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import re
import logging
from engine.guardrails.pii.detector import _COMPILED_PII

logger = logging.getLogger("wrapsec.engine")

# Redaction masks per PII type.
# Every label defined in engine/guardrails/pii/detector.PII_PATTERNS MUST
# have an entry here -- an unknown label falls through to the generic
# [REDACTED] mask, which is a silent regression on the label-specific
# audit signal. The invariant is asserted in test_pii_detector.py.
REDACTION_MASKS = {
    "ITIN":             "[ITIN REDACTED]",
    "SSN":              "[SSN REDACTED]",
    "SSN_RAW":          "[SSN REDACTED]",
    "PASSPORT":         "[PASSPORT REDACTED]",
    "DRIVERS_LICENSE":  "[DL REDACTED]",
    "UK_NIN":           "[UK NIN REDACTED]",
    "CREDIT_CARD":      "[CARD REDACTED]",
    "CREDIT_CARD_LABEL":"[CARD REDACTED]",
    "BANK_ACCOUNT":     "[ACCOUNT REDACTED]",
    "ROUTING_NUMBER":   "[ROUTING REDACTED]",
    "IBAN_STRICT":      "[IBAN REDACTED]",
    "IBAN":             "[IBAN REDACTED]",
    "SWIFT_BIC":        "[SWIFT REDACTED]",
    "EMAIL":            "[EMAIL REDACTED]",
    "PHONE":            "[PHONE REDACTED]",
    "MAC_ADDRESS":      "[MAC REDACTED]",
    "DOB":              "[DOB REDACTED]",
    "MEDICAL_RECORD":   "[MEDICAL REDACTED]",
    "MEDICAL_INFO":     "[MEDICAL REDACTED]",
    "NPI":              "[NPI REDACTED]",
    "PASSWORD":         "[PASSWORD REDACTED]",
    "API_KEY":          "[API KEY REDACTED]",
    "SECRET_KEY":       "[SECRET REDACTED]",
    "STRIPE_KEY":       "[KEY REDACTED]",
    "GITHUB_TOKEN":     "[TOKEN REDACTED]",
    "AWS_KEY":          "[AWS KEY REDACTED]",
    "SLACK_TOKEN":      "[SLACK TOKEN REDACTED]",
    "JWT_TOKEN":        "[JWT REDACTED]",
    "ZIP_CODE":         "[ZIP REDACTED]",
    "ADDRESS":          "[ADDRESS REDACTED]",
}


class PIIRedactor:
    """
    Redacts PII from text by replacing matches with type-specific masks.
    Stateless - returns a new sanitised string, never modifies in place.
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
            # Fail closed - do not return the original text, which may contain
            # unredacted PII. Re-raise so the caller (gateway service) treats
            # this as an error and blocks the request rather than passing raw
            # PII to the client.
            logger.error("PIIRedactor failed: %s", e, exc_info=True)
            raise