# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Detector profile registry.

A DetectorProfile bundles the Tier 1 model (TF-IDF), Tier 2 model (transformer),
rule pattern set, and inference timeout into a single named configuration.

V1 ships with the "general" profile only. Adding an industry-specific profile in v2
is a single registry entry -- no changes to any detector or pipeline code.

Profile selection in v2:
    "detector_profile" field added to the policy model and resolved via the
    existing policy resolver chain. Tenant sets the base profile; departments override.

Model IDs are defined here only. Detector classes receive them as constructor
arguments and never import from this module directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass(frozen=True)
class DetectorProfile:
    name:          str
    tier1_model:   Path    # path to TF-IDF .pkl file
    tier2_model:   str     # HuggingFace model ID
    tier2_timeout: float   # transformer inference timeout in seconds
    rule_patterns: str     # key into rule_patterns package (e.g. "general")
    model_version: str     # logged to audit trail for compliance traceability


PROFILE_REGISTRY: dict[str, DetectorProfile] = {
    "general": DetectorProfile(
        name          = "general",
        tier1_model   = _REPO_ROOT / "models" / "ml_detector.pkl",
        tier2_model   = "protectai/deberta-v3-base-prompt-injection-v2",
        tier2_timeout = 1.5,
        rule_patterns = "general",
        model_version = "1.0.0",
    ),
    # v2 examples (not yet active):
    #
    # "healthcare": DetectorProfile(
    #     name          = "healthcare",
    #     tier1_model   = _REPO_ROOT / "models" / "cache" / "healthcare" / "1.0.0" / "ml_healthcare.pkl",
    #     tier2_model   = "wrapsec/deberta-v3-healthcare-injection-v1",
    #     tier2_timeout = 1.5,
    #     rule_patterns = "healthcare",
    #     model_version = "1.0.0",
    # ),
    #
    # "finance": DetectorProfile(
    #     name          = "finance",
    #     tier1_model   = _REPO_ROOT / "models" / "cache" / "finance" / "1.0.0" / "ml_finance.pkl",
    #     tier2_model   = "wrapsec/deberta-v3-finance-injection-v1",
    #     tier2_timeout = 1.5,
    #     rule_patterns = "finance",
    #     model_version = "1.0.0",
    # ),
}


def get_profile(name: str) -> DetectorProfile:
    """Return the named profile, falling back to general if not found."""
    return PROFILE_REGISTRY.get(name, PROFILE_REGISTRY["general"])
