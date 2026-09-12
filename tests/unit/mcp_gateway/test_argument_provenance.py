# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Tool-call arguments are judged as agent-composed, not as a user prompt.

WHY THIS IS NOT A LABELLING DETAIL. Provenance decides which trust tier the
posture layer applies. `user_prompt` is the TRUSTED tier, so a deployment that
sets an untrusted delta tightens tool definitions and tool results and leaves
arguments at base thresholds -- the one boundary between them, and the last one
before a side effect that may not be reversible.

The chain this closes: a poisoned tool result instructs the agent to call a tool
with attacker-chosen arguments. The result scan may catch the instruction, but
the arguments are the point at which the instruction becomes an action.
"""

from __future__ import annotations

import pytest

from domain.enums import InputSource
from engine.policy.posture.source import EffectiveThresholds
from engine.provenance.registry import SourceRegistry, TrustTier
from mcp_gateway.scanner import (
    SOURCE_TOOL_ARGUMENT,
    SOURCE_TOOL_DEFINITION,
    SOURCE_TOOL_RESULT,
)

AGENT_TOOL_CALL = "agent_tool_call"


# ---------------------------------------------------------------------------
# the vocabulary
# ---------------------------------------------------------------------------

def test_the_source_is_part_of_the_domain_vocabulary():
    """A value the enum does not carry cannot be stored or reported on."""
    assert InputSource.AGENT_TOOL_CALL.value == AGENT_TOOL_CALL


def test_the_gateway_sends_arguments_as_agent_tool_call():
    assert SOURCE_TOOL_ARGUMENT == AGENT_TOOL_CALL, (
        f"arguments are declared as {SOURCE_TOOL_ARGUMENT!r}; if that is a "
        f"trusted-tier source the untrusted delta no longer reaches them"
    )


def test_the_other_two_boundaries_keep_their_classification():
    """The change must not disturb the boundaries either side of it."""
    assert SOURCE_TOOL_DEFINITION == "external_content"
    assert SOURCE_TOOL_RESULT     == "tool_output"


def test_the_three_gateway_sources_are_distinct():
    """Merging them would collapse by-source reporting for the gateway."""
    sources = {SOURCE_TOOL_DEFINITION, SOURCE_TOOL_RESULT, SOURCE_TOOL_ARGUMENT}
    assert len(sources) == 3, sources


# ---------------------------------------------------------------------------
# the tier it resolves to
# ---------------------------------------------------------------------------

def _registry() -> SourceRegistry:
    from config.settings import get_settings

    get_settings.cache_clear()
    return SourceRegistry.from_settings()


def test_the_shipped_defaults_classify_arguments_as_untrusted():
    """The whole point of the change: it must land in the untrusted list."""
    assert _registry().resolve(AGENT_TOOL_CALL).tier is TrustTier.UNTRUSTED, (
        "agent_tool_call is not in the shipped untrusted list, so the untrusted "
        "delta does not reach tool-call arguments"
    )


def test_a_user_prompt_is_still_trusted():
    """Unchanged: a human typing a message is not the agent composing a call."""
    assert _registry().resolve("user_prompt").tier is TrustTier.TRUSTED


@pytest.mark.parametrize("source", ["tool_output", "external_content",
                                    "retrieved_document"])
def test_the_existing_untrusted_sources_are_unchanged(source):
    assert _registry().resolve(source).tier is TrustTier.UNTRUSTED


def test_every_gateway_boundary_now_resolves_untrusted():
    """None of the three is content a person typed."""
    registry = _registry()
    for source in (SOURCE_TOOL_DEFINITION, SOURCE_TOOL_RESULT, SOURCE_TOOL_ARGUMENT):
        assert registry.resolve(source).tier is TrustTier.UNTRUSTED, source


# ---------------------------------------------------------------------------
# the delta actually reaches an argument scan
# ---------------------------------------------------------------------------

def test_an_untrusted_delta_tightens_the_argument_boundary():
    """End of the chain: source -> tier -> posture -> effective thresholds.

    Asserted through the real posture layer, and all the way to the numbers the
    policy engine consults. The registry only classifies; if the delta never
    reached a threshold the classification would be decoration.
    """
    from engine.policy.posture.source import apply_posture, resolve_source_posture

    registry = _registry()
    delta    = 0.1
    base     = (0.7, 0.4)

    argument = resolve_source_posture(registry.resolve(SOURCE_TOOL_ARGUMENT), delta)
    prompt   = resolve_source_posture(registry.resolve("user_prompt"), delta)

    assert argument.threshold_delta == pytest.approx(delta), (
        "no posture delta is applied to tool-call arguments"
    )
    assert prompt.threshold_delta == pytest.approx(0.0)

    tightened = apply_posture(*base, argument)
    unchanged = apply_posture(*base, prompt)

    assert tightened.block    == pytest.approx(base[0] - delta)
    assert tightened.sanitize == pytest.approx(base[1] - delta)
    assert (unchanged.block, unchanged.sanitize) == pytest.approx(base)


def test_a_zero_delta_leaves_the_argument_boundary_unchanged():
    """The feature stays off by default; classification alone changes nothing."""
    from engine.policy.posture.source import apply_posture, resolve_source_posture

    posture = resolve_source_posture(_registry().resolve(SOURCE_TOOL_ARGUMENT), 0.0)
    assert posture.threshold_delta == pytest.approx(0.0)
    assert apply_posture(0.7, 0.4, posture) == EffectiveThresholds(0.7, 0.4)


# ---------------------------------------------------------------------------
# the value survives the client that carries it
# ---------------------------------------------------------------------------

def test_the_sdk_accepts_the_source_the_gateway_sends():
    """The SDK validates input_source locally, BEFORE any request is made.

    A value the server knows but the client rejects would make every argument
    scan raise -- which the gateway fails closed on, so every tool call would be
    refused and the gateway would look broken rather than wrong.
    """
    from wrapsec.core.validation import validate_input_source

    assert validate_input_source(SOURCE_TOOL_ARGUMENT) == SOURCE_TOOL_ARGUMENT


def test_the_published_vocabulary_carries_the_source():
    """The schema vocabulary and the enum must not drift apart."""
    from api.v1.schemas.response import INPUT_SOURCES

    assert SOURCE_TOOL_ARGUMENT in INPUT_SOURCES
    assert set(INPUT_SOURCES) == {e.value for e in InputSource}
