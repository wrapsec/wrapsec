# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from dataclasses import dataclass


@dataclass
class PolicyRules:
    """
    Policy thresholds and configuration.
    Loaded from settings at startup.
    Can be updated at runtime via settings API.
    """
    block_threshold:     float = 0.7
    sanitize_threshold:  float = 0.4
    llm_trigger_threshold: float = 0.2

    def should_block(self, score: float) -> bool:
        return score >= self.block_threshold

    def should_sanitize(self, score: float) -> bool:
        return self.sanitize_threshold <= score < self.block_threshold

    def should_allow(self, score: float) -> bool:
        return score < self.sanitize_threshold

    def should_invoke_llm(self, score: float) -> bool:
        return score >= self.llm_trigger_threshold

    def validate(self) -> None:
        if self.block_threshold <= self.sanitize_threshold:
            raise ValueError(
                f"block_threshold ({self.block_threshold}) must be greater "
                f"than sanitize_threshold ({self.sanitize_threshold})"
            )

    @classmethod
    def from_settings(cls) -> "PolicyRules":
        from config.settings import get_settings
        s = get_settings()
        rules = cls(
            block_threshold       = s.block_threshold,
            sanitize_threshold    = s.sanitize_threshold,
            llm_trigger_threshold = s.llm_trigger_threshold,
        )
        rules.validate()
        return rules