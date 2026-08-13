# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import pytest

from domain.enums import ThreatCategory
from engine.guardrails.pii.detector import PIIDetector


@pytest.fixture
def detector():
    return PIIDetector()


def test_clean_input_returns_zero(detector):
    result = detector.detect("What is the weather today?")
    assert result.score == 0.0
    assert result.triggered is False


def test_email_detected(detector):
    result = detector.detect("My email is john@example.com")
    assert result.triggered is True
    assert ThreatCategory.PII in result.threats
    assert "EMAIL" in result.details["pii_types"]


def test_ssn_detected(detector):
    result = detector.detect("My SSN is 123-45-6789")
    assert result.triggered is True
    assert "SSN" in result.details["pii_types"]


def test_credit_card_detected(detector):
    result = detector.detect("Card number 4111111111111111")
    assert result.triggered is True
    assert "CREDIT_CARD" in result.details["pii_types"]


def test_phone_detected(detector):
    result = detector.detect("Call me at 555-123-4567")
    assert result.triggered is True
    assert "PHONE" in result.details["pii_types"]


def test_password_detected(detector):
    result = detector.detect("Password: mysecret123")
    assert result.triggered is True
    assert "PASSWORD" in result.details["pii_types"]


def test_score_increases_with_multiple_pii(detector):
    single = detector.detect("My email is john@example.com")
    multiple = detector.detect(
        "My email is john@example.com and SSN is 123-45-6789"
    )
    assert multiple.score > single.score


def test_score_capped_at_max(detector):
    result = detector.detect(
        "Email john@example.com SSN 123-45-6789 card 4111111111111111 "
        "password: secret123 phone 555-123-4567"
    )
    assert result.score <= detector.MAX_SCORE


# ── v1.2.0 new recognizers ────────────────────────────────────────────────────

class TestITIN:
    # US ITIN format is 9XX-[7X|8X]-XXXX per IRS spec. Distinct from SSN
    # (which never starts with 9); the pattern is ordered before SSN in
    # the detector so ITINs are labelled correctly.

    def test_itin_detected_with_hyphens(self, detector):
        result = detector.detect("Taxpayer ID 912-70-1234 on file")
        assert result.triggered
        assert "ITIN" in result.details["pii_types"]

    def test_itin_labelled_regardless_of_ssn_overlap(self, detector):
        # ITIN and SSN patterns both match a 9XX-YX-ZZZZ string in the
        # DETECTOR path (which reports every hit); the redactor is where
        # first-match ordering matters (see TestRedactorOrdering below).
        result = detector.detect("912-85-4321")
        assert "ITIN" in result.details["pii_types"]

    def test_regular_ssn_still_labelled_ssn(self, detector):
        # ITIN pattern must NOT swallow real SSNs (leading 9 is the tell).
        result = detector.detect("123-45-6789")
        assert "SSN" in result.details["pii_types"]
        assert "ITIN" not in result.details["pii_types"]


class TestIBAN:

    def test_bare_iban_detected_without_label(self, detector):
        # GB82WEST12345698765432 is the canonical ISO 13616 example.
        result = detector.detect("Please wire funds to GB82WEST12345698765432 today.")
        assert result.triggered
        assert "IBAN_STRICT" in result.details["pii_types"]

    def test_labeled_iban_still_detected(self, detector):
        result = detector.detect("IBAN: DE89370400440532013000")
        assert result.triggered
        assert any(l in result.details["pii_types"] for l in ("IBAN_STRICT", "IBAN"))


class TestSWIFTBIC:
    # Label-anchored on purpose -- see detector.py comment about "STANDARD"
    # and similar 8-letter words otherwise false-positiving.

    def test_swift_bic_8_char_detected(self, detector):
        result = detector.detect("SWIFT: DEUTDEFF for transfer")
        assert result.triggered
        assert "SWIFT_BIC" in result.details["pii_types"]

    def test_swift_bic_11_char_detected(self, detector):
        result = detector.detect("BIC code: CHASUS33XXX for wire")
        assert result.triggered
        assert "SWIFT_BIC" in result.details["pii_types"]

    def test_bare_uppercase_word_does_not_false_positive(self, detector):
        # Regression guard for the label-anchoring decision. detect()
        # returns details=None when nothing triggers, hence the guard.
        result = detector.detect("Our STANDARD procedure is documented.")
        types  = (result.details or {}).get("pii_types") or []
        assert "SWIFT_BIC" not in types


class TestMACAddress:

    def test_mac_colon_separated_detected(self, detector):
        result = detector.detect("Device MAC 00:1A:2B:3C:4D:5E is online")
        assert result.triggered
        assert "MAC_ADDRESS" in result.details["pii_types"]

    def test_mac_hyphen_separated_detected(self, detector):
        result = detector.detect("Windows shows AA-BB-CC-DD-EE-FF")
        assert result.triggered
        assert "MAC_ADDRESS" in result.details["pii_types"]


class TestNPI:

    def test_npi_label_anchored_detected(self, detector):
        result = detector.detect("Provider NPI: 1234567890 verified")
        assert result.triggered
        assert "NPI" in result.details["pii_types"]

    def test_bare_10_digits_does_not_trigger_npi(self, detector):
        # Bare 10-digit numbers include phones, order IDs etc. NPI is
        # intentionally label-anchored; this assertion locks that in.
        result = detector.detect("Order 1234567890 was shipped.")
        types  = (result.details or {}).get("pii_types") or []
        assert "NPI" not in types


class TestJWTToken:

    def test_jwt_detected(self, detector):
        # Minimal but validly-shaped JWT: eyJ.<b64url>.<b64url>.
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJKb2huIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        result = detector.detect(f"Auth header set: Bearer {jwt}")
        assert result.triggered
        assert "JWT_TOKEN" in result.details["pii_types"]


class TestSlackToken:

    def test_slack_bot_token_detected(self, detector):
        result = detector.detect(
            "Slack token exposed: xoxb-1234567890-abcdefghij"
        )
        assert result.triggered
        assert "SLACK_TOKEN" in result.details["pii_types"]

    def test_slack_user_token_detected(self, detector):
        result = detector.detect("token=xoxp-9876543210-zyxwvutsr")
        assert result.triggered
        assert "SLACK_TOKEN" in result.details["pii_types"]


class TestUKNIN:

    def test_uk_nin_detected(self, detector):
        # AB123456C -- valid prefix pair, 6 digits, checksum letter.
        result = detector.detect("NI number AB123456C on file")
        assert result.triggered
        assert "UK_NIN" in result.details["pii_types"]

    def test_uk_nin_invalid_prefix_letters_not_matched(self, detector):
        # DF is a known invalid prefix (D and F are excluded). The bare
        # pattern must NOT hit -- this locks in the char class rule.
        result = detector.detect("Not-a-NIN: DF123456C in the text")
        types  = (result.details or {}).get("pii_types") or []
        assert "UK_NIN" not in types


class TestRedactionMaskCompleteness:
    # Load-bearing invariant: every pattern label must have a purpose-built
    # mask. Falling through to the generic [REDACTED] label loses the
    # per-type audit signal.

    def test_every_pattern_label_has_a_mask(self):
        from engine.guardrails.pii.detector import PII_PATTERNS
        from engine.guardrails.pii.redactor import REDACTION_MASKS

        pattern_labels = {label for _, label in PII_PATTERNS}
        missing = pattern_labels - REDACTION_MASKS.keys()
        assert not missing, f"Missing redaction masks for: {sorted(missing)}"

    def test_pattern_count_is_at_least_30(self):
        # v1.2.0 target: 30 recognizers. Locks in that a future edit which
        # removes a pattern doesn't quietly regress the coverage claim.
        from engine.guardrails.pii.detector import PII_PATTERNS
        assert len(PII_PATTERNS) >= 30


class TestRedactorOrdering:
    # In the redactor, the first pattern that matches consumes the text,
    # so ITIN wins over SSN for 9XX-YX-ZZZZ strings. This is the behavior
    # that the detector-side "co-labelling" test does NOT prove.

    def test_itin_string_gets_itin_mask_not_ssn_mask(self):
        from engine.guardrails.pii.redactor import PIIRedactor
        out, types = PIIRedactor().redact("Taxpayer 912-70-1234")
        assert "[ITIN REDACTED]" in out
        assert "[SSN REDACTED]" not in out
        assert types[0] == "ITIN"

    def test_real_ssn_still_gets_ssn_mask(self):
        from engine.guardrails.pii.redactor import PIIRedactor
        out, types = PIIRedactor().redact("SSN 123-45-6789 on file")
        assert "[SSN REDACTED]" in out
        assert "[ITIN REDACTED]" not in out