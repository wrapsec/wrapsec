# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Every refusal obeys the same contract, whatever produced it.

A refusal is delivered into the context the blocked content was aimed at, so it
carries none of that content. It is a valid result rather than a protocol fault,
because a fault is something an agent commonly retries. And it says nothing about
which detector fired: a message keyed on that would be a tuning oracle, letting a
prober learn which class of payload trips the control.

The rules are checked against every reason the gateway can produce, so a new one
cannot be added that quietly breaks them.
"""

from __future__ import annotations

import pytest

from mcp_gateway import decision as d

# Every reason the gateway itself names, plus the shapes a detection API reports.
# The API's own verdicts are deliberately included: they are NOT in the message
# vocabulary, and the contract has to hold for them too.
_GATEWAY_REASONS = (
    d.TOOL_NOT_RESOLVED,
    d.TOOL_DENIED_BY_POLICY,
    d.UNSUPPORTED_SERVER_REQUEST,
    d.DOWNSTREAM_UNAVAILABLE,
    d.DOWNSTREAM_RESPONSE_UNUSABLE,
    d.SYSTEM_ERROR,
)
_API_REASONS = (
    "PROMPT_INJECTION", "PII_GUARDRAIL_BLOCK", "TOXICITY_GUARDRAIL_BLOCK",
    "JAILBREAK", "CONTENT_TOO_LARGE", "SOMETHING_ADDED_LATER",
)
_ALL_REASONS = _GATEWAY_REASONS + _API_REASONS


@pytest.mark.parametrize("reason", _ALL_REASONS)
@pytest.mark.parametrize("failed", [False, True])
def test_every_refusal_is_a_valid_error_result_with_one_text_part(reason, failed):
    """A valid MCP result, not a protocol fault: a fault gets retried."""
    result = d.refusal_result(d.Refusal(reason=reason, trace_id="t1", failed=failed))

    assert result.is_error is True
    assert len(result.content) == 1
    assert result.content[0].type == "text"
    assert result.content[0].text


@pytest.mark.parametrize("reason", _ALL_REASONS)
def test_every_refusal_carries_a_trace_and_tells_the_agent_not_to_retry(reason):
    text = d.refusal_text(d.Refusal(reason=reason, trace_id="trace-xyz"))

    assert "trace-xyz" in text, "no correlation identifier for the operator"
    assert "Do not retry" in text, "the agent was not told to stop"


@pytest.mark.parametrize("reason", _ALL_REASONS)
def test_no_refusal_leaks_the_reason_code_itself(reason):
    """The code is an audit value. Rendering it would carry detector detail into
    the agent's context and name what was caught."""
    text = d.refusal_text(d.Refusal(reason=reason, trace_id="t1"))

    assert reason not in text, f"the reason code {reason!r} was rendered to the agent"


@pytest.mark.parametrize("reason", _ALL_REASONS)
def test_no_refusal_leaks_the_operator_detail(reason):
    """`detail` is for the server-side record. It names servers, tools and
    arguments, which is exactly what must not be echoed back."""
    secret = "server=internal-db tool=dump_all argument=/etc/shadow"
    text   = d.refusal_text(d.Refusal(reason=reason, trace_id="t1", detail=secret))

    for fragment in ("internal-db", "dump_all", "/etc/shadow"):
        assert fragment not in text, f"{fragment!r} reached the agent"


def test_a_judged_refusal_is_not_reported_as_a_failed_check():
    """The distinction the scanner preserves must survive to the agent.

    Reporting a judgement as an outage is false, and it tells an operator
    reading a transcript that their detector is broken when it is working.
    """
    judged = d.refusal_text(d.Refusal(reason="PROMPT_INJECTION", trace_id="t", failed=False))
    outage = d.refusal_text(d.Refusal(reason=d.SYSTEM_ERROR, trace_id="t", failed=True))

    assert "could not run" not in judged, (
        "content that WAS judged is reported to the agent as an unrun check"
    )
    assert "could not run" in outage
    assert judged != outage


def test_a_failed_check_is_not_reported_as_a_content_judgement():
    """The other direction: an outage must not read as a verdict about the
    content, or an operator will hunt for a payload that does not exist."""
    text = d.refusal_text(d.Refusal(reason="CONTENT_TOO_LARGE", trace_id="t", failed=True))

    assert "refused by a security policy" not in text
    assert "could not run" in text


@pytest.mark.parametrize("reason", _API_REASONS)
def test_detector_verdicts_share_one_message(reason):
    """No per-detector wording: a message keyed on which detector fired would
    let a prober learn which class of payload was caught."""
    text = d.refusal_text(d.Refusal(reason=reason, trace_id="t1", failed=False))
    baseline = d.refusal_text(d.Refusal(reason="PROMPT_INJECTION", trace_id="t1", failed=False))

    if reason != "CONTENT_TOO_LARGE":       # that one is a gateway-side limit
        assert text == baseline, f"{reason!r} has its own wording"


def test_the_refusal_names_the_gateway_so_an_agent_can_tell_who_refused():
    """Distinguishes a security refusal from a tool's own error message."""
    text = d.refusal_text(d.Refusal(reason=d.SYSTEM_ERROR, trace_id="t1"))

    assert text.startswith("[WrapSec]")
