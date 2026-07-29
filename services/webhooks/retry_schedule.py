# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Retry schedule for outbound webhook delivery (v1.3.0).

Pure policy module. Given the attempt number that JUST failed, returns
how many seconds a delivery worker should wait before trying again --
or None to signal that the message has exhausted its retries and
belongs on the dead-letter stream.

The delivery worker in workers/webhook_delivery.py is deliberately
agnostic about backoff; the concrete DeliveryHandler consults this
module to compute retry_in_s on failure. Keeping the schedule in a
dedicated module means:

  * The values are trivial to unit test in isolation.
  * Tests can monkeypatch the tuple for fast retry-flow tests.
  * A future v2 feature (per-tenant tuning) has a single call site
    to reroute through.

Schedule choice: 5s -> 5m -> 30m -> 2h -> 5h -> 10h -> 10h.

That is the industry-standard 8-attempt schedule (initial + 7 retries)
spanning ~27.6h, adopted by the widely-used open-source webhook
delivery reference implementation. Rationale:

  * 5s covers the vast majority of transient receiver blips (deploy
    rollovers, ephemeral 502s from a load balancer).
  * Growing intervals back off aggressively before a struggling
    receiver gets pounded further.
  * ~27.6h total is long enough to survive an overnight incident on
    the receiver side without being so long that DLQ operators are
    waiting days to see a failing endpoint surfaced.

No jitter is applied. Fixed intervals give operators predictable
receiver-side runbooks and simpler load reasoning. A jitter knob can
be added behind config later if enterprise deployments need it.

Message id (`msg_id` in the payload) is stable across retries so a
compliant receiver can dedupe repeat deliveries as the same logical
event -- this is a queue-layer property, not a schedule-layer one,
but it is what makes retries safe to apply here.
"""

from __future__ import annotations


# Delay between attempt N (which just failed) and attempt N+1.
# Index i corresponds to failure of attempt (i+1).
RETRY_SCHEDULE_SECONDS: tuple[int, ...] = (
    5,       #     5 seconds
    300,     #     5 minutes
    1_800,   #    30 minutes
    7_200,   #     2 hours
    18_000,  #     5 hours
    36_000,  #    10 hours
    36_000,  #    10 hours
)


# Total attempts made against a receiver before we give up and DLQ:
# the initial attempt plus one attempt per schedule slot.
MAX_ATTEMPTS: int = 1 + len(RETRY_SCHEDULE_SECONDS)


def next_retry_delay(attempt_number: int) -> int | None:
    """
    Return seconds to wait before the next delivery attempt, or None if
    `attempt_number` was the last attempt this message is allowed.

    `attempt_number` is the attempt that JUST failed (1-based to match
    the payload's `attempt_number` field, which starts at 1 for the
    initial emit).

    None is the caller's cue to return DeliveryOutcome(DLQ,
    dlq_reason="retries_exhausted") rather than requeue.

    Raises ValueError for attempt_number < 1 -- that is a caller bug
    (payload should always start at 1); we want it surfaced loudly
    rather than silently defaulting.
    """
    if attempt_number < 1:
        raise ValueError(f"attempt_number must be >= 1, got {attempt_number}")
    idx = attempt_number - 1
    if idx >= len(RETRY_SCHEDULE_SECONDS):
        return None
    return RETRY_SCHEDULE_SECONDS[idx]
