# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import re

from domain.enums import ThreatCategory
from engine.detection.base import BaseDetector, DetectionResult
from engine.detection.limits import clamp_for_regex

# ── PII Pattern definitions ───────────────────────────────────
#
# Pattern order matters. The redactor and detector iterate sequentially
# and first match wins, so more specific patterns must precede broader
# ones. ITIN before SSN (both fit \d{3}-\d{2}-\d{4} but ITIN's leading
# 9 disambiguates); IBAN_STRICT before the label-anchored IBAN so a bare
# IBAN in the wild is caught even without an "IBAN:" prefix.
#
# Coverage spans 30 entity types (identity, financial, contact, medical,
# international identifiers). Where standard checksum validators exist
# (mod-97 for IBAN, Luhn for NPI) this file does not yet apply them --
# the current architecture is pure regex. Adding a validator hook is a
# follow-up; the strict regex length + format prefixes below already
# reject most false positives.

PII_PATTERNS = [
    # Identity
    (r"\b9\d{2}[- ]?[78]\d[- ]?\d{4}\b",                                "ITIN"),
    (r"\b\d{3}-\d{2}-\d{4}\b",                                          "SSN"),
    (r"\b(ssn|social\s+security(\s+number|\s+no|\s+#)?)\s*:?\s*\d{9}\b", "SSN_RAW"),
    (r"\bpassport\s*(number|no|#)?\s*:?\s*[A-Z]{1,2}\d{6,9}\b",         "PASSPORT"),
    (r"\b(driver'?s?\s*license|dl)\s*(number|no|#)?\s*:?\s*[A-Z0-9]{5,15}\b", "DRIVERS_LICENSE"),
    # HMRC-published prefix rule: certain leading pairs (DF/FN/GB/IQ/UV/NK etc.)
    # are never issued; the char class encodes the allowed letters directly
    # (D, F, I, Q, U, V excluded from both positions).
    (r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",                             "UK_NIN"),

    # Financial
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "CREDIT_CARD"),
    (r"\b(credit\s*card|card\s*number|cc\s*number)\s*:?\s*[\d\s\-]{13,19}\b", "CREDIT_CARD_LABEL"),
    (r"\b(bank\s*account|account\s*number)\s*:?\s*\d{8,17}\b",           "BANK_ACCOUNT"),
    (r"\b(routing\s*number)\s*:?\s*\d{9}\b",                             "ROUTING_NUMBER"),
    # ISO 13616: 2 country letters + 2 check digits + up to 30 alphanumerics.
    # No mod-97 validation yet -- see file header note.
    (r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",                                "IBAN_STRICT"),
    (r"\b(iban)\s*:?\s*[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b", "IBAN"),
    # ISO 9362 BIC/SWIFT: bank(4 letters) + country(2 letters) + location(2
    # alphanum) + optional branch(3 alphanum). Label-anchored: bare 8-letter
    # tokens like "STANDARD" would otherwise match and swamp the redactor
    # with false positives on ordinary uppercase text.
    (r"\b(swift|bic)\s*(code|number)?\s*:?\s*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", "SWIFT_BIC"),

    # Contact
    (r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",          "EMAIL"),
    (r"\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b",      "PHONE"),
    # IEEE 802 MAC. Both hyphen and colon separators are common in the wild
    # (Windows vs Unix output). Cisco dot notation (xxxx.xxxx.xxxx) is not
    # covered here -- add if we see it in real traffic.
    (r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",                    "MAC_ADDRESS"),

    # Medical
    (r"\b(date\s+of\s+birth|dob)\s*:?\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b", "DOB"),
    (r"\b(medical\s+record|mrn|patient\s+id)\s*:?\s*[A-Z0-9]{5,15}\b",  "MEDICAL_RECORD"),
    (r"\b(diagnosis|prescription|medication)\s*:?\s*[a-zA-Z\s]{3,50}\b", "MEDICAL_INFO"),
    # US National Provider Identifier: 10 digits. Bare 10-digit numbers
    # false-positive too aggressively (phone number chunks, order IDs), so
    # this is label-anchored. Luhn-like check digit validation not applied
    # yet (see file header note).
    (r"\b(npi|national\s+provider\s+id(?:entifier)?)\s*:?\s*\d{10}\b",  "NPI"),

    # Credentials
    (r"\b(password|passwd|pwd)\s*[:=]\s*\S+",                            "PASSWORD"),
    (r"\b(api[\s_]?key|apikey|api[\s_]?token)\s*[:=]\s*[A-Za-z0-9\-_]{16,}", "API_KEY"),
    (r"\b(secret[\s_]?key|secret[\s_]?token)\s*[:=]\s*[A-Za-z0-9\-_]{16,}", "SECRET_KEY"),
    (r"\bsk[-_](live|test)[-_][A-Za-z0-9]{20,}\b",                      "STRIPE_KEY"),
    (r"\bghp_[A-Za-z0-9]{36}\b",                                         "GITHUB_TOKEN"),
    (r"\b(aws[\s_]?access[\s_]?key[\s_]?id)\s*[:=]\s*[A-Z0-9]{20}\b",  "AWS_KEY"),
    # Slack OAuth tokens: xoxa (app), xoxb (bot), xoxo (workspace),
    # xoxp (user), xoxr (refresh). The xox prefix is Slack-specific; FP
    # essentially zero.
    (r"\bxox[abopr]-[A-Za-z0-9\-]{10,}\b",                              "SLACK_TOKEN"),
    # JWT: base64url(header).base64url(payload).base64url(signature).
    # Header always base64-encodes to a JSON object starting with '{',
    # which produces the eyJ prefix -- so eyJ.eyJ.<anything> is a very
    # tight signature for a real JWT.
    (r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",   "JWT_TOKEN"),

    # Location
    (r"\b(zip\s*code|zipcode|postal\s*code)\s*:?\s*\d{5}(?:-\d{4})?\b", "ZIP_CODE"),
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
            # ReDoS defense: bound the input size fed into regex engine.
            # See engine/detection/limits.py for rationale.
            text = clamp_for_regex(text)

            found:   dict[str, list[str]] = {}

            for pattern, label in _COMPILED_PII:
                try:
                    matches = pattern.findall(text)
                except re.error:
                    # A single broken pattern must not disable the whole detector.
                    continue
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