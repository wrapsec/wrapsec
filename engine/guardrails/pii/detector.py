import re
from engine.detection.base import BaseDetector, DetectionResult
from domain.enums import ThreatCategory


# ── PII Pattern definitions ───────────────────────────────────

PII_PATTERNS = [
    # Identity
    (r"\b\d{3}-\d{2}-\d{4}\b",                                          "SSN"),
    (r"\b\d{9}\b",                                                        "SSN_RAW"),
    (r"\bpassport\s*(number|no|#)?\s*:?\s*[A-Z]{1,2}\d{6,9}\b",         "PASSPORT"),
    (r"\b(driver'?s?\s*license|dl)\s*(number|no|#)?\s*:?\s*[A-Z0-9]{5,15}\b", "DRIVERS_LICENSE"),

    # Financial
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "CREDIT_CARD"),
    (r"\b(credit\s*card|card\s*number|cc\s*number)\s*:?\s*[\d\s\-]{13,19}\b", "CREDIT_CARD_LABEL"),
    (r"\b(bank\s*account|account\s*number)\s*:?\s*\d{8,17}\b",           "BANK_ACCOUNT"),
    (r"\b(routing\s*number)\s*:?\s*\d{9}\b",                             "ROUTING_NUMBER"),
    (r"\b(iban)\s*:?\s*[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b", "IBAN"),

    # Contact
    (r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",          "EMAIL"),
    (r"\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b",      "PHONE"),

    # Medical
    (r"\b(date\s+of\s+birth|dob)\s*:?\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b", "DOB"),
    (r"\b(medical\s+record|mrn|patient\s+id)\s*:?\s*[A-Z0-9]{5,15}\b",  "MEDICAL_RECORD"),
    (r"\b(diagnosis|prescription|medication)\s*:?\s*[a-zA-Z\s]{3,50}\b", "MEDICAL_INFO"),

    # Credentials
    (r"\b(password|passwd|pwd)\s*[:=]\s*\S+",                            "PASSWORD"),
    (r"\b(api[\s_]?key|apikey|api[\s_]?token)\s*[:=]\s*[A-Za-z0-9\-_]{16,}", "API_KEY"),
    (r"\b(secret[\s_]?key|secret[\s_]?token)\s*[:=]\s*[A-Za-z0-9\-_]{16,}", "SECRET_KEY"),
    (r"\bsk[-_](live|test)[-_][A-Za-z0-9]{20,}\b",                      "STRIPE_KEY"),
    (r"\bghp_[A-Za-z0-9]{36}\b",                                         "GITHUB_TOKEN"),
    (r"\b(aws[\s_]?access[\s_]?key[\s_]?id)\s*[:=]\s*[A-Z0-9]{20}\b",  "AWS_KEY"),

    # Location
    (r"\b\d{5}(?:-\d{4})?\b",                                            "ZIP_CODE"),
    (r"\b(address)\s*:?\s*\d+\s+[A-Za-z\s]{3,50}(street|st|avenue|ave|road|rd|blvd)\b", "ADDRESS"),
]

_COMPILED_PII: list[tuple[re.Pattern, str]] = [
    (re.compile(pattern, re.IGNORECASE), label)
    for pattern, label in PII_PATTERNS
]


class PIIDetector(BaseDetector):

    # Score increases with number of PII types found
    BASE_SCORE   = 0.65
    PER_MATCH    = 0.08
    MAX_SCORE    = 0.95

    @property
    def name(self) -> str:
        return "pii_detector"

    def detect(self, text: str) -> DetectionResult:
        try:
            found:   dict[str, list[str]] = {}

            for pattern, label in _COMPILED_PII:
                matches = pattern.findall(text)
                if matches:
                    found[label] = matches if isinstance(matches[0], str) else [str(m) for m in matches]

            if not found:
                return DetectionResult.clean(self.name)

            score = min(
                self.BASE_SCORE + (len(found) - 1) * self.PER_MATCH,
                self.MAX_SCORE,
            )

            return DetectionResult(
                score     = round(score, 4),
                threats   = [ThreatCategory.PII],
                triggered = True,
                detector  = self.name,
                details   = {"pii_types": list(found.keys())},
            )

        except Exception:
            return DetectionResult.clean(self.name)