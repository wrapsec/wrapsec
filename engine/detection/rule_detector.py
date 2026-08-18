# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import re

from engine.detection.base import BaseDetector, DetectionResult
from engine.detection.limits import clamp_for_regex
from engine.detection.rule_patterns.general import COMPILED_REGISTRY

# In v2, RuleDetector will accept a profile parameter and load the appropriate
# pattern set from engine.detection.rule_patterns.<profile>. For v1 the general
# compiled registry is always used.
_COMPILED = COMPILED_REGISTRY


class RuleDetector(BaseDetector):

    @property
    def name(self) -> str:
        return "rule_detector"

    def detect(self, text: str) -> DetectionResult:
        try:
            # ReDoS defense: bound the input size fed into regex engine.
            # See engine/detection/limits.py for rationale.
            text = clamp_for_regex(text)

            threats    = []
            max_score  = 0.0
            details    = {}

            for compiled_patterns, category, base_score in _COMPILED:
                matched = []
                for p in compiled_patterns:
                    try:
                        if p.search(text):
                            matched.append(p.pattern)
                    except re.error:
                        # A single broken pattern must not disable the whole detector.
                        continue
                if matched:
                    threats.append(category)
                    # Score is the max across all matching categories, not a sum.
                    # Multi-category hits do not boost the score - each category
                    # has a calibrated base_score that already reflects severity.
                    # The list of threat categories in `threats` carries the
                    # multi-category signal for policy and audit purposes.
                    max_score = max(max_score, base_score)
                    details[category.value] = matched

            return DetectionResult(
                score     = max_score,
                threats   = threats,
                triggered = max_score > 0.0,
                detector  = self.name,
                details   = details if details else None,
            )

        except Exception:
            return DetectionResult.clean(self.name)