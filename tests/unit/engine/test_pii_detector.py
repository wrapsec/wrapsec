# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import pytest
from engine.guardrails.pii.detector import PIIDetector
from domain.enums import ThreatCategory


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