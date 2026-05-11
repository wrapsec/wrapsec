# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import pytest
from services.policy_resolver import deep_merge, system_defaults, determine_policy_source


def test_deep_merge_null_child_inherits_parent():
    parent = {"thresholds": {"block": 0.7, "sanitize": 0.4}}
    result = deep_merge(parent, None)
    assert result == parent


def test_deep_merge_null_field_inherits():
    parent = {"thresholds": {"block": 0.7, "sanitize": 0.4}}
    child  = {"thresholds": {"block": None}}
    result = deep_merge(parent, child)
    assert result["thresholds"]["block"]    == 0.7
    assert result["thresholds"]["sanitize"] == 0.4


def test_deep_merge_explicit_field_overrides():
    parent = {"thresholds": {"block": 0.7, "sanitize": 0.4}}
    child  = {"thresholds": {"block": 0.5}}
    result = deep_merge(parent, child)
    assert result["thresholds"]["block"]    == 0.5
    assert result["thresholds"]["sanitize"] == 0.4


def test_deep_merge_nested_partial_override():
    parent = {
        "guardrails": {
            "pii": {
                "enabled":            True,
                "block_threshold":    0.7,
                "sanitize_threshold": 0.4,
            }
        }
    }
    child = {
        "guardrails": {
            "pii": {
                "block_threshold": 0.5
            }
        }
    }
    result = deep_merge(parent, child)
    assert result["guardrails"]["pii"]["enabled"]            == True
    assert result["guardrails"]["pii"]["block_threshold"]    == 0.5
    assert result["guardrails"]["pii"]["sanitize_threshold"] == 0.4


def test_deep_merge_all_null_inherits_completely():
    parent = {"thresholds": {"block": 0.7, "sanitize": 0.4}}
    child  = {"thresholds": {"block": None, "sanitize": None}}
    result = deep_merge(parent, child)
    assert result["thresholds"]["block"]    == 0.7
    assert result["thresholds"]["sanitize"] == 0.4


def test_deep_merge_does_not_mutate_parent():
    parent = {"thresholds": {"block": 0.7}}
    child  = {"thresholds": {"block": 0.5}}
    result = deep_merge(parent, child)
    assert parent["thresholds"]["block"] == 0.7
    assert result["thresholds"]["block"] == 0.5


def test_system_defaults_returns_complete_policy():
    policy = system_defaults()
    assert "detection"  in policy
    assert "thresholds" in policy
    assert "guardrails" in policy
    assert "llm"        in policy
    assert "rate_limit" in policy
    assert policy["thresholds"]["block"]    > 0
    assert policy["thresholds"]["sanitize"] >= 0
    assert policy["thresholds"]["block"]    > policy["thresholds"]["sanitize"]


def test_policy_source_no_overrides():
    source = determine_policy_source(None, None)
    assert source == "system_default"


def test_policy_source_dept_override():
    source = determine_policy_source(
        dept_override = {"thresholds": {"block": 0.5}},
        app_override  = None,
    )
    assert source == "department_override"


def test_policy_source_app_override():
    source = determine_policy_source(
        dept_override = {"thresholds": {"block": 0.5}},
        app_override  = {"thresholds": {"block": 0.6}},
    )
    assert source == "application_override"


def test_policy_source_tenant_only():
    # tenant_override no longer used in policy resolution - global_policy removed from chain.
    # With no dept or app override, result is always system_default.
    source = determine_policy_source(
        dept_override = None,
        app_override  = None,
    )
    assert source == "system_default"