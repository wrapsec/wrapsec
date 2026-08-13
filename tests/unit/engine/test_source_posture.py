# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Posture resolver + Policy Adapter (source dimension).

Locks in the opt-in semantics: only untrusted origins carry a delta, trusted and
unknown are no-ops, the adapter tightens both thresholds by the same delta
(preserving block > sanitize), clamps at 0 without inverting, and is the identity
when the delta is 0.
"""

from engine.policy.posture.source import (
    Posture,
    apply_posture,
    resolve_source_posture,
)
from engine.provenance.registry import SourceDescriptor, TrustTier


def _descriptor(tier: TrustTier) -> SourceDescriptor:
    return SourceDescriptor(input_source="x", tier=tier)


# --- resolver ---

def test_untrusted_carries_delta():
    p = resolve_source_posture(_descriptor(TrustTier.UNTRUSTED), 0.1)
    assert p.dimension == "source"
    assert p.tier == "untrusted"
    assert p.threshold_delta == 0.1


def test_trusted_gets_base_posture():
    p = resolve_source_posture(_descriptor(TrustTier.TRUSTED), 0.1)
    assert p.threshold_delta == 0.0


def test_unknown_gets_base_posture():
    p = resolve_source_posture(_descriptor(TrustTier.UNKNOWN), 0.1)
    assert p.threshold_delta == 0.0


# --- adapter ---

def test_zero_delta_is_identity():
    eff = apply_posture(0.7, 0.4, Posture("source", "trusted", 0.0))
    assert (eff.block, eff.sanitize) == (0.7, 0.4)


def test_delta_tightens_both_thresholds():
    eff = apply_posture(0.7, 0.4, Posture("source", "untrusted", 0.1))
    assert round(eff.block, 4) == 0.6
    assert round(eff.sanitize, 4) == 0.3
    # Same shift on both preserves the block > sanitize ordering.
    assert eff.block > eff.sanitize


def test_large_delta_clamps_without_inverting():
    # A delta big enough to clamp block to 0 also clamps sanitize to 0; because
    # base block > sanitize, the two meet at 0 and never invert.
    eff = apply_posture(0.7, 0.4, Posture("source", "untrusted", 0.9))
    assert eff.block == 0.0
    assert eff.sanitize == 0.0
    assert eff.block >= eff.sanitize


def test_negative_delta_is_treated_as_zero():
    # Defense in depth: even if a negative delta reached the adapter, it must
    # never loosen thresholds (settings validation rejects it upstream too).
    eff = apply_posture(0.7, 0.4, Posture("source", "untrusted", -0.2))
    assert (eff.block, eff.sanitize) == (0.7, 0.4)
