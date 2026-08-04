# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Input normalization for evasion-resistant detection.

Normalization is a deterministic preprocessing subsystem. It never performs
policy decisions, never modifies downstream prompts, and never contributes
directly to risk scoring. Its sole responsibility is to produce canonical and
alternate representations for detection.

Detect on the canonical view, forward the original to the LLM. Extend by
appending stages in stages.py (language normalization, more decode-views) or, in
future, adding an extractor layer upstream (HTML parsing, OCR) that turns a
non-text source into text before normalization.

    from engine.normalization import normalize
    result = normalize(user_text)
    for view_text in result.texts():   # canonical + decode-views
        ... run detection ...
    if result.obfuscated:              # risk signal
        ...
"""

from engine.normalization.pipeline import PIPELINE_VERSION, normalize
from engine.normalization.types import (
    AppliedStage,
    DetectionView,
    NormalizedInput,
    StageOutput,
)

__all__ = [
    "normalize",
    "PIPELINE_VERSION",
    "NormalizedInput",
    "DetectionView",
    "AppliedStage",
    "StageOutput",
]
