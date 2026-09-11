# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Every way a scan can end, and what the gateway does with each.

The distinction that matters here is between a BLOCK and a FAILURE. One says the
content was judged dangerous; the other says the control did not run. Both
refuse, but only one is evidence about the content, and an operator reading an
audit trail needs to tell them apart.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from mcp_gateway.scanner import Scanner, Verdict


@dataclass
class _Result:
    """Stands in for a scan result from the detection API."""

    decision:       str = "ALLOW"
    primary_reason: str = "NO_THREAT_DETECTED"
    trace_id:       str = "api-trace"
    sanitized_input: str | None = None

    def is_blocked(self):      return self.decision == "BLOCK"
    def is_sanitized(self):    return self.decision == "SANITIZE"
    def is_system_error(self): return self.primary_reason == "SYSTEM_ERROR"


class _Client:
    def __init__(self, result=None, raises=None):
        self._result = result
        self._raises = raises
        self.calls   = []

    async def scan(self, text, *, mode, input_source):
        self.calls.append({"text": text, "mode": mode, "source": input_source})
        if self._raises:
            raise self._raises
        return self._result or _Result()


@pytest.mark.asyncio
async def test_clean_content_is_allowed():
    scanner = Scanner(_Client())
    verdict = await scanner.scan("hello", source="external_content", trace_id="t")

    assert verdict.allowed and not verdict.blocked and not verdict.failed


@pytest.mark.asyncio
async def test_a_block_is_a_block_and_names_its_reason():
    client  = _Client(_Result(decision="BLOCK", primary_reason="PROMPT_INJECTION"))
    verdict = await Scanner(client).scan("x", source="external_content", trace_id="t")

    assert verdict.blocked and not verdict.failed
    assert verdict.reason == "PROMPT_INJECTION"


@pytest.mark.asyncio
async def test_a_detector_fault_blocks_and_is_marked_as_a_failure():
    """The API reports a fault on the result rather than raising, so that flag
    has to be read: without it a failed scan arrives looking like a clean one."""
    client  = _Client(_Result(decision="BLOCK", primary_reason="SYSTEM_ERROR"))
    verdict = await Scanner(client).scan("x", source="external_content", trace_id="t")

    assert verdict.blocked and verdict.failed
    assert verdict.reason == "SYSTEM_ERROR"


@pytest.mark.asyncio
async def test_an_unreachable_api_blocks_unjudged_content():
    """Fail closed. The content was not inspected, and forwarding it would make
    the control optional."""
    client  = _Client(raises=OSError("connection refused"))
    verdict = await Scanner(client).scan("x", source="external_content", trace_id="t")

    assert verdict.blocked and verdict.failed
    assert verdict.reason == "SYSTEM_ERROR"


@pytest.mark.asyncio
async def test_sanitized_content_comes_back_for_the_caller_to_use():
    client  = _Client(_Result(decision="SANITIZE", primary_reason="PII_GUARDRAIL_SANITIZE",
                              sanitized_input="redacted"))
    verdict = await Scanner(client).scan("x", source="tool_output", trace_id="t")

    assert not verdict.blocked
    assert verdict.sanitized == "redacted"


@pytest.mark.asyncio
async def test_oversized_content_is_blocked_not_truncated():
    """A verdict taken on the first N characters does not cover what was sent,
    and yet looks like one that does."""
    client  = _Client()
    scanner = Scanner(client, max_chars=10)

    verdict = await scanner.scan("x" * 50, source="external_content", trace_id="t")

    assert verdict.blocked and verdict.failed
    assert verdict.reason == "CONTENT_TOO_LARGE"
    assert client.calls == [], "oversized content was sent to the detector anyway"


@pytest.mark.asyncio
async def test_content_exactly_at_the_bound_is_still_scanned():
    """The limit is a maximum, not an exclusive bound; an off-by-one here would
    silently refuse legitimate content."""
    client  = _Client()
    verdict = await Scanner(client, max_chars=10).scan(
        "x" * 10, source="external_content", trace_id="t",
    )

    assert not verdict.blocked
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_empty_content_is_not_a_block():
    """An absent description is not evidence of anything, and sending it would
    spend a scan to learn nothing."""
    client  = _Client()
    verdict = await Scanner(client).scan("", source="external_content", trace_id="t")

    assert not verdict.blocked and not verdict.failed
    assert client.calls == []


@pytest.mark.asyncio
async def test_the_configured_mode_and_source_reach_the_api():
    client = _Client()
    await Scanner(client, mode="fast").scan("x", source="tool_output", trace_id="t")

    assert client.calls[0]["mode"]   == "fast"
    assert client.calls[0]["source"] == "tool_output"


@pytest.mark.asyncio
async def test_the_api_trace_id_is_preferred_when_it_returns_one():
    """An operator following a refusal needs the identifier the API recorded,
    not the one the gateway invented before calling it."""
    client  = _Client(_Result(trace_id="from-api"))
    verdict = await Scanner(client).scan("x", source="external_content", trace_id="local")

    assert verdict.trace_id == "from-api"


def test_a_verdict_that_is_not_blocked_is_allowed():
    assert Verdict(blocked=False, sanitized=None, reason="x", trace_id="t").allowed
    assert not Verdict(blocked=True, sanitized=None, reason="x", trace_id="t").allowed
