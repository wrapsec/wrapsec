# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""A slow output scan must not stall the process, and must not let output out.

The output guard is regex over model output. That text is not attacker-AUTHORED,
but a caller who shapes the prompt shapes what the model emits, so a
catastrophically backtracking string is reachable from outside. Run
synchronously on the event loop it does not slow one request: it stalls every
coroutine in the process, including other tenants' requests.

The input guard has been bounded off-thread with a timeout for exactly this
reason. These tests hold the output side to the same contract, and to the same
fail-closed direction: a guard that could not finish must BLOCK, never allow.

`test_a_slow_output_scan_does_not_block_the_event_loop` is the one that proves
the actual claim. A timeout test alone passes against an implementation that
blocks the loop for the full timeout duration -- the point is not only that the
wait ends, but that everything else keeps running while it lasts.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from engine.guardrails.output_guard import OutputGuard


@pytest.fixture
def guard():
    return OutputGuard()


async def test_a_timed_out_scan_blocks_rather_than_allowing(guard, monkeypatch):
    """Fail closed. An ALLOW here would return unscanned model output to the
    caller, which is the one thing an output guard exists to prevent."""
    def _hang(_text):
        time.sleep(5.0)
        raise AssertionError("should have been aborted by the timeout")

    monkeypatch.setattr(guard, "inspect", _hang)

    start  = time.perf_counter()
    result = await guard.inspect_bounded("model output", timeout_seconds=0.2)
    elapsed = time.perf_counter() - start

    assert elapsed < 2.0, f"took {elapsed:.2f}s -- the time bound did not fire"
    assert result.decision == "BLOCK"


async def test_a_timeout_is_reported_as_a_fault_not_as_a_content_block(guard, monkeypatch):
    """The two must stay distinguishable in the audit trail.

    A guard that REFUSED the content and a guard that could not RUN are
    different events: the first is a policy decision about the output, the
    second is a system failure that happens to be safe. Collapsing them would
    make an outage read as a wave of blocked responses.
    """
    def _hang(_text):
        time.sleep(5.0)

    monkeypatch.setattr(guard, "inspect", _hang)

    result = await guard.inspect_bounded("model output", timeout_seconds=0.2)

    assert result.failed is True, "a timeout was not marked as a guard failure"
    assert result.primary_reason == "SYSTEM_ERROR"
    assert result.sanitized_text is None


async def test_a_normal_scan_is_unaffected(guard):
    """The control. Without it, a helper hard-wired to BLOCK would satisfy
    every assertion above."""
    result = await guard.inspect_bounded("a perfectly ordinary reply", timeout_seconds=5.0)

    assert result.decision == "ALLOW"
    assert result.failed is False


async def test_a_slow_output_scan_does_not_block_the_event_loop(guard, monkeypatch):
    """The actual claim being fixed.

    A second coroutine must keep running while the first sits inside a slow
    scan. Run on the loop, the sleep below holds the only thread and the ticker
    cannot advance; run off-thread, it advances throughout.
    """
    def _slow(_text):
        time.sleep(0.6)
        raise AssertionError("should have been aborted by the timeout")

    monkeypatch.setattr(guard, "inspect", _slow)

    ticks = 0

    async def _ticker():
        nonlocal ticks
        for _ in range(20):
            await asyncio.sleep(0.02)
            ticks += 1

    await asyncio.gather(
        guard.inspect_bounded("model output", timeout_seconds=0.3),
        _ticker(),
    )

    assert ticks >= 10, (
        f"the event loop advanced only {ticks} times while an output scan was "
        "running: the scan is holding the loop, so one pathological reply "
        "stalls every other request in the process"
    )
