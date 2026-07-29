# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.retry_schedule.

The schedule is a customer-visible contract: when a receiver flakes,
operators can predict exactly when they will see the next attempt land
in their access logs, and DLQ triage teams know the wall-clock window
before a message gives up. These tests pin the exact values so a
casual "tweak the numbers" edit fails loudly in CI.
"""

from __future__ import annotations

import pytest

from services.webhooks.retry_schedule import (
    MAX_ATTEMPTS,
    RETRY_SCHEDULE_SECONDS,
    next_retry_delay,
)


# ─── Schedule shape ─────────────────────────────────────────────────

def test_schedule_is_the_documented_seven_slot_tuple():
    """Any change to these numbers is a customer-visible protocol change --
    update docs + release notes before touching this test."""
    assert RETRY_SCHEDULE_SECONDS == (5, 300, 1800, 7200, 18000, 36000, 36000)


def test_max_attempts_is_initial_plus_seven_retries():
    assert MAX_ATTEMPTS == 8


def test_schedule_is_monotonically_non_decreasing():
    """Growing intervals are the whole point -- a shorter delay after a
    longer one would defeat the back-off. Duplicates are allowed (10h twice
    at the tail is intentional)."""
    prev = 0
    for delay in RETRY_SCHEDULE_SECONDS:
        assert delay >= prev, f"schedule regressed at {delay=} after {prev=}"
        prev = delay


def test_all_entries_are_positive_ints():
    for delay in RETRY_SCHEDULE_SECONDS:
        assert isinstance(delay, int)
        assert delay > 0


def test_total_window_is_roughly_twenty_seven_hours():
    """Guard against silently blowing the ~day-scale operator expectation."""
    total_h = sum(RETRY_SCHEDULE_SECONDS) / 3600
    assert 20 <= total_h <= 40, f"schedule now spans {total_h:.1f}h"


# ─── next_retry_delay: happy path ───────────────────────────────────

def test_first_attempt_failure_waits_five_seconds():
    """5s covers the most common receiver flake -- deploy rollovers, ephemeral 502s."""
    assert next_retry_delay(1) == 5


def test_second_attempt_failure_waits_five_minutes():
    assert next_retry_delay(2) == 300


def test_third_attempt_failure_waits_thirty_minutes():
    assert next_retry_delay(3) == 1800


def test_fourth_attempt_failure_waits_two_hours():
    assert next_retry_delay(4) == 7200


def test_fifth_attempt_failure_waits_five_hours():
    assert next_retry_delay(5) == 18000


def test_sixth_attempt_failure_waits_ten_hours():
    assert next_retry_delay(6) == 36000


def test_seventh_attempt_failure_waits_ten_hours():
    """Tail is 10h twice so a receiver that recovers between attempts 7 and 8
    still gets its message before the ~27h window closes."""
    assert next_retry_delay(7) == 36000


# ─── next_retry_delay: exhaustion ───────────────────────────────────

def test_eighth_attempt_failure_returns_none():
    """None is the handler's cue to DLQ with reason=retries_exhausted --
    never silently drop."""
    assert next_retry_delay(8) is None


def test_far_beyond_schedule_still_returns_none():
    """Defensive: a bug that manages to bump attempt_number past MAX must
    still terminate cleanly at DLQ, not raise deep in delivery."""
    assert next_retry_delay(100) is None


def test_return_type_is_int_or_none():
    for n in range(1, MAX_ATTEMPTS + 3):
        result = next_retry_delay(n)
        assert result is None or isinstance(result, int)


# ─── next_retry_delay: input validation ─────────────────────────────

def test_zero_attempt_number_raises_value_error():
    """attempt_number is 1-based (payload sets it to 1 on emit) --
    a 0 here is a caller bug we want surfaced loudly."""
    with pytest.raises(ValueError):
        next_retry_delay(0)


def test_negative_attempt_number_raises_value_error():
    with pytest.raises(ValueError):
        next_retry_delay(-1)
