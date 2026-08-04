# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Value types for the normalization pipeline.

The pipeline turns a raw prompt into a NormalizedInput: one CANONICAL string
(always-on, low-FPR folding) that feeds the rule and ML detectors, plus zero or
more DetectionView candidates from lossy/ambiguous decodings (leetspeak, base64,
...) that are scanned separately -- the detector takes the max signal across
views without the FPR cost of folding them into the canonical text.

AppliedStage is the single source of per-stage provenance: it drives the
obfuscation risk signal, the telemetry (what was stripped/folded/decoded), and
the Prometheus metrics. Metrics and telemetry are CONSUMERS of these records,
not separate systems.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectionView:
    """An alternative text to scan alongside the canonical form."""
    text:  str
    kind:  str          # "canonical" | "base64" | "rot13" | "leet" | ...
    depth: int = 0      # decode-nesting depth (0 = canonical / single decode)


@dataclass(frozen=True)
class AppliedStage:
    """What one stage did on one input. Consumed by telemetry + metrics."""
    name:       str
    version:    str
    changed:    bool          # did it alter the canonical text or produce views
    count:      int           # chars folded / zero-width stripped / views produced
    latency_ms: float
    suspicious: bool = True    # firing indicates obfuscation (vs mundane NFKC/whitespace)
    error:      str | None = None   # fail-soft: a raising stage is recorded, not fatal


@dataclass(frozen=True)
class NormalizedInput:
    """The normalized representation of a prompt, consumed by detection."""
    canonical: str
    views:     list[DetectionView] = field(default_factory=list)
    stages:    list[AppliedStage]  = field(default_factory=list)
    version:   str = ""            # auto-derived from the active stage composition

    def texts(self) -> list[str]:
        """Canonical first, then every view -- the full set detection scans."""
        return [self.canonical, *(v.text for v in self.views)]

    @property
    def obfuscated(self) -> bool:
        """True if a SUSPICIOUS stage fired (invisibles stripped, confusables
        folded, a hidden encoding decoded) -- a risk signal. Mundane NFKC /
        whitespace collapse do not count, so benign text does not trip it."""
        return any(s.changed and s.suspicious for s in self.stages)


@dataclass(frozen=True)
class StageOutput:
    """What a stage returns. `text` is a new canonical string (None = unchanged);
    `views` are candidates to add; `count` is the change/production count."""
    text:  str | None = None
    views: tuple[DetectionView, ...] = ()
    count: int = 0
