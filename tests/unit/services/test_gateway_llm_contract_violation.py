# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The proxy step handles the state its own contract says cannot happen.

`GatewayService._call_llm_async` returns `(content, error)` with exactly one
set. That holds by construction -- three returns, all consistent: the exception
path returns `(None, "provider_unavailable")`, an empty completion returns
`(None, "provider_empty_response")`, and the success path returns non-empty
content with no error.

The step that consumes it read `raw_output` under `elif llm_invoked:`, relying
on that contract without stating it. The type checker reported the read as
possibly unbound, and the repository's typecheck gate had been red on it since
the branch was introduced.

WHY THE STATE IS HANDLED RATHER THAN ASSERTED AWAY. The question is not whether
the contract holds today -- it does -- but what the code DOES if it stops
holding. Traced before changing anything: the output guard answers ALLOW for
empty text, so a None completion passed the guard, `output` resolved to None,
and the caller received a SUCCESSFUL response carrying no completion with
`llm_invoked` true. That is the same outage-rendered-as-an-answer failure the
provider_error branch exists to prevent, reached from the other side.

So it now fails closed, and these tests pin that behaviour rather than asserting
the state is unreachable. A test that asserts unreachability protects nothing:
it passes both before and after the invariant breaks.
"""

from unittest.mock import patch

import pytest

from domain.entities.request import IncomingRequest
from domain.enums import DecisionType, DetectionMode, ExecutionMode
from services.gateway.service import GatewayService


@pytest.fixture
def svc():
    return GatewayService()


def _proxy_request():
    return IncomingRequest(
        input          = "Please summarise the attached quarterly report.",
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.PROXY,
        model          = "test-model",
    )


class _Completion:
    def __init__(self, content):
        self.content = content


# ── the normal path, unchanged ───────────────────────────────────────────────

async def test_a_real_completion_still_reaches_the_caller(svc):
    """The control. Every assertion below is satisfied by a gateway that blocks
    everything, so the working path has to be pinned alongside them."""
    async def _ok(*_a, **_kw):
        return _Completion("The report shows revenue up 4% quarter on quarter.")

    with patch("clients.get_llm_client") as _client:
        _client.return_value.complete = _ok
        result = await svc.process(_proxy_request())

    assert result.provider_error is None
    assert result.decision.output == "The report shows revenue up 4% quarter on quarter."
    assert result.decision.decision != DecisionType.BLOCK


# ── the state the checker said was reachable ─────────────────────────────────

async def test_a_contract_violation_fails_closed_instead_of_serving_an_empty_success(svc):
    """`_call_llm_async` forced to return neither content nor error.

    This cannot happen through its own code paths, which is exactly why it is
    simulated at the seam rather than through the provider: the point is to pin
    what the CONSUMER does, not to prove the producer is correct.
    """
    async def _neither(*_a, **_kw):
        return None, None

    with patch.object(svc, "_call_llm_async", _neither):
        result = await svc.process(_proxy_request())

    assert result.decision.decision == DecisionType.BLOCK, (
        "the gateway served a non-BLOCK verdict for a completion it never "
        "received; before this was handled it answered a SUCCESS carrying no "
        "output at all"
    )
    assert result.decision.output is None
    assert result.decision.risk_score.value == pytest.approx(1.0)
    assert result.decision.primary_reason == "SYSTEM_ERROR", (
        "the failure was reported as a verdict about content rather than as a "
        "control that could not run"
    )


async def test_the_contract_violation_is_not_confused_with_a_provider_outage(svc):
    """A provider outage deliberately does NOT force BLOCK -- the scan ran and
    its verdict is real evidence. The two must stay distinguishable, or an
    outage starts reading as an attack in the audit trail."""
    async def _outage(*_a, **_kw):
        return None, "provider_unavailable"

    with patch.object(svc, "_call_llm_async", _outage):
        outage = await svc.process(_proxy_request())

    assert outage.provider_error == "provider_unavailable"
    assert outage.decision.output is None
    assert outage.decision.decision != DecisionType.BLOCK, (
        "a provider outage was collapsed into a BLOCK, which reports an "
        "infrastructure failure as an attack"
    )


# ── the producer's half of the contract, so the consumer's gate stays honest ──

@pytest.mark.parametrize("completion,expected_error", [
    (_Completion("real content"), None),
    (_Completion(""),             "provider_empty_response"),
])
async def test_the_producer_sets_exactly_one_of_content_and_error(svc, completion, expected_error):
    async def _return(*_a, **_kw):
        return completion

    with patch("clients.get_llm_client") as _client:
        _client.return_value.complete = _return
        content, error = await svc._call_llm_async("prompt", "test-model")

    assert (content is None) != (error is None), (
        f"both or neither were set: content={content!r} error={error!r}"
    )
    assert error == expected_error


async def test_the_producer_reports_an_exception_as_an_error_not_as_content(svc):
    async def _raise(*_a, **_kw):
        raise RuntimeError("simulated provider outage")

    with patch("clients.get_llm_client") as _client:
        _client.return_value.complete = _raise
        content, error = await svc._call_llm_async("prompt", "test-model")

    assert content is None
    assert error == "provider_unavailable"
