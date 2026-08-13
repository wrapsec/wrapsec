# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Source Registry: classify an input_source into a trust tier.

Covers the default taxonomy, the unknown tier and its Zero-Trust escalation,
case/whitespace normalization, the None fallback, and the untrusted-first
precedence that keeps a config mistake from downgrading an origin.
"""

from engine.provenance.registry import SourceRegistry, TrustTier


def _registry(**kwargs):
    defaults = {
        "trusted": ["user_prompt"],
        "untrusted": ["tool_output", "retrieved_document", "external_content"],
    }
    defaults.update(kwargs)
    return SourceRegistry(**defaults)


def test_trusted_source_resolves_trusted():
    assert _registry().resolve("user_prompt").tier == TrustTier.TRUSTED


def test_untrusted_sources_resolve_untrusted():
    reg = _registry()
    for src in ("tool_output", "retrieved_document", "external_content"):
        assert reg.resolve(src).tier == TrustTier.UNTRUSTED


def test_unrecognized_source_is_unknown_by_default():
    assert _registry().resolve("agent_memory").tier == TrustTier.UNKNOWN


def test_unknown_escalates_to_untrusted_when_configured():
    reg = _registry(treat_unknown_as_untrusted=True)
    assert reg.resolve("agent_memory").tier == TrustTier.UNTRUSTED


def test_none_falls_back_to_user_prompt():
    # Callers that omit the source get the trusted default, never unknown.
    assert _registry().resolve(None).tier == TrustTier.TRUSTED


def test_case_and_whitespace_are_normalized():
    d = _registry().resolve("  Retrieved_Document  ")
    assert d.tier == TrustTier.UNTRUSTED
    assert d.input_source == "retrieved_document"


def test_untrusted_wins_on_overlap_misconfig():
    # A source listed in both lists must resolve to the stricter tier so a
    # config mistake cannot quietly downgrade an origin to trusted.
    reg = SourceRegistry(trusted=["x"], untrusted=["x"])
    assert reg.resolve("x").tier == TrustTier.UNTRUSTED
