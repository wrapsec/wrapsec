# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Posture: turn provenance into effective policy thresholds.

Dimension-agnostic by design. Today only the source dimension is implemented
(source.py); tenant / application / environment postures would be sibling
resolvers producing the same Posture shape, consumed by the same Policy Adapter.
Nothing here touches detection -- it only reshapes the thresholds the policy
engine applies.

    from engine.policy.posture import (
        resolve_source_posture, apply_posture,
    )
    posture   = resolve_source_posture(descriptor, untrusted_delta)
    effective = apply_posture(block_threshold, sanitize_threshold, posture)
"""

from engine.policy.posture.source import (
    EffectiveThresholds,
    Posture,
    apply_posture,
    resolve_source_posture,
)

__all__ = [
    "Posture",
    "EffectiveThresholds",
    "resolve_source_posture",
    "apply_posture",
]
