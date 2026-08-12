# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for email delivery settings (v1.8.3).

Verifies the defaults/bounds are derived from the REAL retry schedule and that
coercion clamps a stored record into valid ranges rather than raising.
"""

from __future__ import annotations

import pytest

from services.email.settings import (
    MAX_MAX_ATTEMPTS,
    MIN_MAX_ATTEMPTS,
    _coerce,
    _defaults,
    validate_email_settings,
)
from services.webhooks.retry_schedule import MAX_ATTEMPTS, RETRY_SCHEDULE_SECONDS


def test_bounds_derive_from_the_real_schedule():
    # The ceiling is exactly initial + one per backoff interval.
    assert MAX_MAX_ATTEMPTS == MAX_ATTEMPTS == 1 + len(RETRY_SCHEDULE_SECONDS)
    assert MIN_MAX_ATTEMPTS == 1


def test_defaults_are_enabled_full_schedule():
    d = _defaults()
    assert d.notifications_enabled is True
    assert d.max_attempts == MAX_ATTEMPTS
    assert d.retention_days >= 1


def test_coerce_none_returns_defaults():
    assert _coerce(None) == _defaults()


def test_coerce_clamps_max_attempts_into_range():
    assert _coerce({"max_attempts": 9999}).max_attempts == MAX_MAX_ATTEMPTS
    assert _coerce({"max_attempts": 0}).max_attempts == MIN_MAX_ATTEMPTS
    assert _coerce({"max_attempts": 3}).max_attempts == 3


def test_coerce_bad_types_fall_back_to_defaults():
    d = _defaults()
    c = _coerce({"max_attempts": "abc", "retention_days": None, "notifications_enabled": 0})
    assert c.max_attempts == d.max_attempts
    assert c.retention_days == d.retention_days
    assert c.notifications_enabled is False  # 0 -> False (explicit off is honored)


def test_coerce_rejects_sub_one_retention():
    assert _coerce({"retention_days": 0}).retention_days == _defaults().retention_days


def test_validate_accepts_valid_and_rejects_out_of_range():
    validate_email_settings(notifications_enabled=True, max_attempts=MAX_ATTEMPTS, retention_days=30)
    with pytest.raises(ValueError):
        validate_email_settings(notifications_enabled=True, max_attempts=MAX_ATTEMPTS + 1, retention_days=30)
    with pytest.raises(ValueError):
        validate_email_settings(notifications_enabled=True, max_attempts=0, retention_days=30)
    with pytest.raises(ValueError):
        validate_email_settings(notifications_enabled=True, max_attempts=3, retention_days=0)
