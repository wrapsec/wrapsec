# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.circuit_breaker.

The 120h default is a customer-visible SLA on when a broken endpoint
stops receiving events. These tests pin the boundary conditions so a
"just bump it a bit" edit fails loudly in CI, and cover the invariants
that make the sweep job safe (NULL never disables, timer measured from
the first failure not the latest).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from services.webhooks.circuit_breaker import (
    DEFAULT_THRESHOLD_HOURS,
    should_disable,
)


# ─── Policy constants ───────────────────────────────────────────────

def test_default_threshold_is_120_hours():
    """Any change here is a customer-visible SLA change -- update docs +
    release notes before touching this test."""
    assert DEFAULT_THRESHOLD_HOURS == 120


# ─── should_disable: healthy path ───────────────────────────────────

def test_null_first_failure_never_disables():
    """A healthy endpoint has first_failure_at=NULL. Disabling one of
    these would take out endpoints that just successfully delivered."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    assert should_disable(None, now) is False


def test_null_first_failure_never_disables_regardless_of_threshold():
    """Even with an aggressive 1h threshold, NULL still means healthy."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    assert should_disable(None, now, threshold_hours=1) is False


# ─── should_disable: inside grace window ────────────────────────────

def test_fresh_failure_does_not_disable():
    """Failure one second ago -- still deep inside the grace window."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now - timedelta(seconds=1)
    assert should_disable(first_failure, now) is False


def test_one_hour_of_failures_does_not_disable():
    """A single-hour outage is well below the 120h SLA."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now - timedelta(hours=1)
    assert should_disable(first_failure, now) is False


def test_119_hours_of_failures_does_not_disable():
    """One hour under threshold: still inside grace, keep trying."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now - timedelta(hours=119)
    assert should_disable(first_failure, now) is False


def test_just_under_threshold_does_not_disable():
    """One second under threshold: strict '<' semantics on the boundary."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now - timedelta(hours=120, seconds=-1)
    assert should_disable(first_failure, now) is False


# ─── should_disable: at/past grace window ───────────────────────────

def test_exactly_at_threshold_disables():
    """Boundary case: elapsed == threshold means the full grace window
    has passed. Retire the endpoint rather than grant another minute."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now - timedelta(hours=120)
    assert should_disable(first_failure, now) is True


def test_just_over_threshold_disables():
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now - timedelta(hours=120, seconds=1)
    assert should_disable(first_failure, now) is True


def test_week_of_failures_disables():
    """A week of continuous failure is unambiguously past the SLA."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now - timedelta(days=7)
    assert should_disable(first_failure, now) is True


# ─── should_disable: custom threshold ───────────────────────────────

def test_custom_threshold_shorter_disables_sooner():
    """Enterprise deployments may want a tighter window; the policy
    honors the caller-supplied threshold, not just the default."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now - timedelta(hours=25)
    assert should_disable(first_failure, now, threshold_hours=24) is True
    assert should_disable(first_failure, now, threshold_hours=48) is False


def test_custom_threshold_longer_defers_disable():
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now - timedelta(hours=200)
    assert should_disable(first_failure, now, threshold_hours=240) is False


# ─── should_disable: input validation ───────────────────────────────

def test_zero_threshold_raises_value_error():
    """A zero threshold would disable every endpoint on the next tick.
    That is always a caller bug -- surface loudly."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    with pytest.raises(ValueError):
        should_disable(now, now, threshold_hours=0)


def test_negative_threshold_raises_value_error():
    now = datetime(2026, 7, 29, 12, 0, 0)
    with pytest.raises(ValueError):
        should_disable(now, now, threshold_hours=-1)


# ─── Clock-skew defense ─────────────────────────────────────────────

def test_first_failure_in_the_future_does_not_disable():
    """DB clock skew or a bogus write could put first_failure_at in
    the future. The elapsed-time comparison naturally handles this
    (negative delta < any positive threshold) -- confirm we do not
    accidentally disable a healthy endpoint on a bad timestamp."""
    now = datetime(2026, 7, 29, 12, 0, 0)
    first_failure = now + timedelta(hours=1)
    assert should_disable(first_failure, now) is False
