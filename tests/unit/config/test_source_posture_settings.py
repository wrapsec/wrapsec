# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Settings validation for source-aware posture.

A negative untrusted_threshold_delta would loosen thresholds for exactly the
origins that warrant more scrutiny, so boot must fail on a sign typo. The
defaults keep the feature off (delta 0) and classify the built-in sources.
"""

import pytest

from config.settings import Settings


def _settings(**overrides) -> Settings:
    # secret_key / admin_api_key come from the test environment; override only
    # the posture fields under test.
    return Settings(**overrides)


def test_negative_delta_rejected():
    s = _settings(untrusted_threshold_delta=-0.1)
    with pytest.raises(ValueError, match="untrusted_threshold_delta"):
        s.validate_source_posture()


def test_zero_delta_ok():
    s = _settings(untrusted_threshold_delta=0.0)
    s.validate_source_posture()  # must not raise


def test_positive_delta_ok():
    s = _settings(untrusted_threshold_delta=0.15)
    s.validate_source_posture()  # must not raise


def test_defaults_are_feature_off_and_classify_builtin_sources():
    s = _settings()
    assert s.untrusted_threshold_delta == 0.0
    assert s.treat_unknown_as_untrusted is False
    assert "user_prompt" in s.trusted_input_sources
    assert "retrieved_document" in s.untrusted_input_sources
