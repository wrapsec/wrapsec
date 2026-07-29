# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Circuit-breaker policy for outbound webhook endpoints (v1.3.0).

Pure policy module. Given an endpoint's `first_failure_at` timestamp,
the current wall-clock, and the configured grace threshold, decides
whether that endpoint has been failing long enough to be auto-disabled.

The state machine driving this decision lives on WebhookEndpointModel:

  * `first_failure_at IS NULL`   - endpoint is healthy (last delivery
                                   was a success, or the endpoint has
                                   never been used).
  * `first_failure_at = t0`      - a delivery failed at t0, and every
                                   attempt since has also failed. The
                                   field is set once by the first
                                   failure and cleared by the next
                                   success; it is NOT reset by
                                   subsequent failures, so the timer
                                   measures continuous unavailability.
  * disabled once now - t0       - the endpoint has been down for the
    exceeds the threshold          full grace window; a sweep job
                                   flips `disabled = True` and stops
                                   fanning new events to it.

The threshold defaults to 120 hours (5 days), matching the industry
convention adopted by widely-used open-source webhook delivery
platforms. Rationale:

  * ~27.6h retry schedule (retry_schedule.py) can span an overnight
    incident; 120h lets several such messages fail across a longer
    outage before the endpoint is retired.
  * Long enough that a customer who is asleep at 2am gets a chance to
    fix things during business hours the next day, on both sides of a
    weekend.
  * Short enough that a genuinely abandoned URL stops consuming
    delivery-worker capacity within a week.

Keeping the decision in a dedicated module means:
  * The threshold and boundary conditions are trivial to unit test.
  * Tests can monkeypatch the constant for fast lifecycle tests.
  * A future per-tenant threshold (v2) has a single call site to
    reroute through.
"""

from __future__ import annotations

from datetime import datetime, timedelta


# Default grace window before an endpoint that has been continuously
# failing gets auto-disabled. Overridable per-install via
# WEBHOOK_CIRCUIT_BREAKER_HOURS in settings; kept here as the source
# of truth so unit tests can pin the constant without touching config.
DEFAULT_THRESHOLD_HOURS: int = 120


def should_disable(
    first_failure_at: datetime | None,
    now:              datetime,
    threshold_hours:  int = DEFAULT_THRESHOLD_HOURS,
) -> bool:
    """
    Return True if the endpoint has been failing long enough to disable.

    Semantics:
      * `first_failure_at is None`     -> False (healthy, no timer).
      * `now - first_failure_at < gap` -> False (still inside grace).
      * `now - first_failure_at >= gap`-> True  (past grace, disable).

    Boundary case (elapsed == threshold) returns True: an endpoint that
    has been down for exactly 120h has had its full grace window and
    should be retired rather than given another minute of chances.

    Raises ValueError for a non-positive threshold. Zero would disable
    every endpoint on the next tick and is always a caller bug.
    """
    if threshold_hours <= 0:
        raise ValueError(
            f"threshold_hours must be > 0, got {threshold_hours}"
        )
    if first_failure_at is None:
        return False
    return (now - first_failure_at) >= timedelta(hours=threshold_hours)
