# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
L3: property-based fuzz test for the rule detector.

Hypothesis generates arbitrary strings (up to 128 KiB - twice the regex clamp
so we also exercise the truncation path) and drives them through
RuleDetector.detect. The invariants we hold across every input:

  1. detect() never raises. If a pattern crashes on a specific input, the
     inner try/except must swallow it and produce a clean-result fallback.
     A crash here would kill the detector and force C1 fail-closed BLOCK
     on every subsequent request.

  2. The returned DetectionResult always has a score in [0.0, 1.0]. A score
     outside that range would break the risk scorer's weighting and the
     policy engine's threshold comparisons.

  3. Every call completes under a per-call time budget (2 seconds - matches
     H2 detector_timeout_seconds default). If any input takes longer, it
     is a candidate ReDoS payload that would have hung a request pre-H2.
     H2 catches this at runtime; this test catches it at build time so a
     new pattern that regresses cannot land unnoticed.
"""

import time

import pytest
from hypothesis import given, settings, HealthCheck, strategies as st

from engine.detection.rule_detector import RuleDetector


_TIME_BUDGET_SECONDS = 2.0

# Legitimate prompts have arbitrary text - do not restrict to printable ASCII.
# Deliberately allow control characters, high-bit code points, and long runs
# of the same byte so pathological backtracking patterns get exercised.
_TEXT = st.text(min_size=0, max_size=128 * 1024)


@pytest.fixture(scope="module")
def detector() -> RuleDetector:
    return RuleDetector()


@given(text=_TEXT)
@settings(
    max_examples             = 200,
    deadline                 = None,          # per-example deadline handled below
    suppress_health_check    = [HealthCheck.too_slow],
)
def test_rule_detector_never_raises_and_stays_in_budget(detector, text):
    start  = time.perf_counter()
    result = detector.detect(text)
    elapsed = time.perf_counter() - start

    # Invariant 3 - time budget. Reported before shape checks so a regression
    # here surfaces as "took too long", not "assertion on some numeric field".
    assert elapsed < _TIME_BUDGET_SECONDS, (
        f"rule detector took {elapsed:.3f}s on input len={len(text)}; "
        f"possible ReDoS pattern - budget was {_TIME_BUDGET_SECONDS}s"
    )

    # Invariant 2 - score is a proper probability
    assert 0.0 <= result.score <= 1.0, (
        f"score {result.score} outside [0, 1] for input len={len(text)}"
    )

    # detector name is stable - guards against a regression that renames it
    # under our feet and breaks downstream lookups
    assert result.detector == "rule_detector"
