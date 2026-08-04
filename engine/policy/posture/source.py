# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Posture + Policy Adapter (source dimension).

The posture layer sits between provenance (which classifies an origin) and the
policy engine (which applies thresholds). It computes, per request, how the
base thresholds should shift given the input's trust tier -- and nothing else.

Two dimension-agnostic pieces plus one source-specific resolver:
  - Posture           : a value object carrying a trust tier and the threshold
                        delta to apply. Named Posture, not SourcePosture, so a
                        future Tenant / Application / Environment posture is a
                        sibling resolver producing the same shape, no rename.
  - apply_posture()   : the Policy Adapter -- a pure function
                        (base thresholds, Posture) -> effective thresholds.
  - resolve_source_posture() : the source-dimension resolver, mapping a
                        SourceDescriptor to a Posture.

Detection never enters here; this only reshapes the thresholds the policy engine
consults. The whole layer is a no-op (identity) when the delta is 0.
"""

from dataclasses import dataclass

from engine.provenance.registry import SourceDescriptor, TrustTier


@dataclass(frozen=True)
class Posture:
    """A policy posture for one dimension of a request.

    dimension       - which posture this is ("source" today; "tenant",
                      "application", "environment" are anticipated siblings).
    tier            - the trust tier that produced it (for explainability).
    threshold_delta - amount to LOWER the block/sanitize thresholds. 0.0 means
                      "no adjustment" (base posture / feature off).
    """
    dimension:       str
    tier:            str
    threshold_delta: float = 0.0


@dataclass(frozen=True)
class EffectiveThresholds:
    """The block/sanitize thresholds after posture adjustment, handed to the
    policy engine in place of the base values."""
    block:    float
    sanitize: float


def resolve_source_posture(
    descriptor:      SourceDescriptor,
    untrusted_delta: float,
) -> Posture:
    """Map a source descriptor to a Posture.

    Only UNTRUSTED origins carry the delta; TRUSTED and UNKNOWN get base posture
    (delta 0). Escalating UNKNOWN to UNTRUSTED is the Source Registry's job
    (treat_unknown_as_untrusted), so by the time we get here the tier already
    reflects that choice.
    """
    delta = untrusted_delta if descriptor.tier == TrustTier.UNTRUSTED else 0.0
    return Posture(
        dimension       = "source",
        tier            = descriptor.tier.value,
        threshold_delta = delta,
    )


def apply_posture(
    block_threshold:    float,
    sanitize_threshold: float,
    posture:            Posture,
) -> EffectiveThresholds:
    """Policy Adapter: shift base thresholds by the posture delta.

    Tightening lowers BOTH thresholds by the same delta, which preserves the
    block > sanitize ordering, and clamps at 0. Because block > sanitize always
    holds for the base values, a delta large enough to clamp block to 0 also
    clamps sanitize to 0 (the two meet at 0, never invert). A delta of 0 returns
    the base thresholds unchanged -- the feature-off identity path.

    Pure function: the strategy (subtractive delta today; multiplicative,
    per-threat, or learned later) can change here without touching the registry
    or the policy engine.
    """
    delta = max(0.0, posture.threshold_delta)
    if delta == 0.0:
        return EffectiveThresholds(block=block_threshold, sanitize=sanitize_threshold)
    return EffectiveThresholds(
        block    = max(0.0, block_threshold - delta),
        sanitize = max(0.0, sanitize_threshold - delta),
    )
