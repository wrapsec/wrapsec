# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Provenance: classify where scanned content came from.

A package (not a single module) from the start, so provenance can grow --
source descriptors, metadata, per-source detector hints -- without a later
restructure. Today it exposes the Source Registry, which maps an input_source
to a trust tier. Classification only; it makes no policy decision (that is the
job of engine/policy/posture) and never touches detection.

    from engine.provenance import SourceRegistry
    descriptor = SourceRegistry.from_settings().resolve("retrieved_document")
    descriptor.tier  # TrustTier.UNTRUSTED
"""

from engine.provenance.registry import SourceDescriptor, SourceRegistry, TrustTier

__all__ = [
    "SourceDescriptor",
    "SourceRegistry",
    "TrustTier",
]
