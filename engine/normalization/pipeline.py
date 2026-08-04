# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Normalization pipeline runner.

Applies the ordered, self-describing stages, enforcing the hard resource limits
centrally so no stage can bypass them. Each stage runs fail-soft (a raising
stage is recorded on its AppliedStage and skipped, never fatal), is timed, and
contributes one AppliedStage record -- the single source for the obfuscation
risk signal, telemetry, and metrics.

The pipeline version is derived from the active stage composition, so any change
to which stages run (or their versions) changes the version automatically.
"""

from __future__ import annotations

import hashlib
import logging
from time import perf_counter

from engine.normalization.limits import MAX_VIEWS, MAX_VIEW_BYTES
from engine.normalization.stages import STAGES
from engine.normalization.types import (
    AppliedStage,
    DetectionView,
    NormalizedInput,
    StageOutput,
)

logger = logging.getLogger("wrapsec.normalization")


def _derive_version() -> str:
    spec = ",".join(f"{s.name}:{s.version}" for s in STAGES if s.enabled)
    return hashlib.sha256(spec.encode()).hexdigest()[:8]


PIPELINE_VERSION = _derive_version()


def normalize(text: str) -> NormalizedInput:
    """Normalize a prompt into its canonical form plus decode-views, with full
    per-stage provenance. Pure and side-effect-free (metrics are emitted by the
    caller from the returned AppliedStage records)."""
    canonical: str = text
    views:   list[DetectionView] = []
    applied: list[AppliedStage]  = []

    for stage in STAGES:
        if not stage.enabled:
            continue

        t0    = perf_counter()
        error = None
        out   = StageOutput()
        try:
            out = stage.fn(canonical)
        except Exception as exc:  # fail-soft: never let a stage break detection
            error = f"{type(exc).__name__}: {exc}"
            logger.error("normalization stage %s failed: %s", stage.name, exc)
        latency_ms = (perf_counter() - t0) * 1000.0

        changed = False
        if out.text is not None and out.text != canonical:
            canonical = out.text
            changed   = True

        for v in out.views:                     # enforce the hard caps centrally
            if len(views) >= MAX_VIEWS:
                break
            capped = v.text[:MAX_VIEW_BYTES]
            views.append(DetectionView(text=capped, kind=v.kind, depth=v.depth))
            changed = True

        applied.append(AppliedStage(
            name       = stage.name,
            version    = stage.version,
            changed    = changed,
            count      = out.count,
            latency_ms = round(latency_ms, 4),
            suspicious = stage.suspicious,
            error      = error,
        ))

    return NormalizedInput(
        canonical = canonical,
        views     = views,
        stages    = applied,
        version   = PIPELINE_VERSION,
    )
