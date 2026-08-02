# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.time -- the single source of truth for time.

These pin the aware-UTC contract: utc_now is aware, ensure_utc normalizes any
input to UTC, to_iso_z always emits a 'Z' suffix with millisecond precision,
and parse_utc_iso round-trips both 'Z' and offset forms back to aware UTC.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from services.time import (
    utc_now, ensure_utc, to_iso_z, parse_utc_iso, date_range_bounds,
)


# --- utc_now ----------------------------------------------------------

def test_utc_now_is_timezone_aware_utc():
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


# --- ensure_utc -------------------------------------------------------

def test_ensure_utc_treats_naive_as_utc():
    naive = datetime(2026, 8, 2, 9, 15, 42)
    aware = ensure_utc(naive)
    assert aware.tzinfo is not None
    assert aware.utcoffset() == timedelta(0)
    assert aware.hour == 9  # not shifted -- read as UTC, not local


def test_ensure_utc_converts_other_zone_to_utc():
    plus_five = timezone(timedelta(hours=5))
    value = datetime(2026, 8, 2, 14, 15, 42, tzinfo=plus_five)
    aware = ensure_utc(value)
    assert aware.utcoffset() == timedelta(0)
    assert aware.hour == 9  # 14:15 +05:00 -> 09:15 UTC


# --- to_iso_z ---------------------------------------------------------

def test_to_iso_z_emits_z_suffix_millisecond_precision():
    value = datetime(2026, 8, 2, 9, 15, 42, 123000, tzinfo=timezone.utc)
    assert to_iso_z(value) == "2026-08-02T09:15:42.123Z"


def test_to_iso_z_never_emits_offset():
    value = datetime(2026, 8, 2, 9, 15, 42, 123000, tzinfo=timezone.utc)
    out = to_iso_z(value)
    assert out.endswith("Z")
    assert "+00:00" not in out


def test_to_iso_z_normalizes_offset_input():
    plus_five = timezone(timedelta(hours=5))
    value = datetime(2026, 8, 2, 14, 15, 42, 500000, tzinfo=plus_five)
    assert to_iso_z(value) == "2026-08-02T09:15:42.500Z"


def test_to_iso_z_accepts_naive_as_utc():
    value = datetime(2026, 8, 2, 9, 15, 42, 0)
    assert to_iso_z(value) == "2026-08-02T09:15:42.000Z"


# --- parse_utc_iso ----------------------------------------------------

def test_parse_utc_iso_accepts_z_suffix():
    dt = parse_utc_iso("2026-08-02T09:15:42.123Z")
    assert dt.utcoffset() == timedelta(0)
    assert dt == datetime(2026, 8, 2, 9, 15, 42, 123000, tzinfo=timezone.utc)


def test_parse_utc_iso_accepts_explicit_offset():
    dt = parse_utc_iso("2026-08-02T14:15:42+05:00")
    assert dt.utcoffset() == timedelta(0)
    assert dt.hour == 9  # converted to UTC


def test_parse_utc_iso_treats_naive_as_utc():
    dt = parse_utc_iso("2026-08-02T09:15:42")
    assert dt.utcoffset() == timedelta(0)
    assert dt.hour == 9


def test_parse_utc_iso_round_trips_to_iso_z():
    original = datetime(2026, 8, 2, 9, 15, 42, 123000, tzinfo=timezone.utc)
    assert parse_utc_iso(to_iso_z(original)) == original


def test_parse_utc_iso_raises_on_garbage():
    with pytest.raises(ValueError):
        parse_utc_iso("not-a-timestamp")


# --- date_range_bounds ------------------------------------------------

def test_date_range_bounds_none_none():
    assert date_range_bounds(None, None) == (None, None)


def test_date_range_bounds_from_date_only_is_start_of_day():
    from_dt, to_dt = date_range_bounds("2026-04-16", None)
    assert to_dt is None
    assert from_dt == datetime(2026, 4, 16, 0, 0, 0, tzinfo=timezone.utc)


def test_date_range_bounds_to_date_only_extends_to_end_of_day():
    _, to_dt = date_range_bounds(None, "2026-04-16")
    assert to_dt == datetime(2026, 4, 16, 23, 59, 59, 999999, tzinfo=timezone.utc)


def test_date_range_bounds_to_with_time_is_not_double_suffixed():
    # A full ISO `to` must be used as-is (the old `to + "T23:59:59"` path would
    # have produced an invalid double-T string).
    _, to_dt = date_range_bounds(None, "2026-04-16T08:30:00Z")
    assert to_dt == datetime(2026, 4, 16, 8, 30, 0, tzinfo=timezone.utc)


def test_date_range_bounds_to_with_offset_normalized_to_utc():
    _, to_dt = date_range_bounds(None, "2026-04-16T13:30:00+05:00")
    assert to_dt == datetime(2026, 4, 16, 8, 30, 0, tzinfo=timezone.utc)


def test_date_range_bounds_raises_on_garbage():
    with pytest.raises(ValueError):
        date_range_bounds("nonsense", None)
