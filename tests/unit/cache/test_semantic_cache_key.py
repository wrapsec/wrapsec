# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The semantic cache key must name the scope a verdict was reached in.

The cache stores ALLOW verdicts. Keyed on tenant alone it returned one
department's ALLOW to another, because departments and applications may tighten
policy below the tenant's: two requests inside one tenant can resolve to
different thresholds and different enabled layers. The stricter scope's policy
was never consulted on a hit, so the tightening had no effect for an input any
other scope had already been allowed.

These tests pin the key's inputs. They exercise `policy_identity` and
`_cache_key` directly rather than through Redis, so they run in the unit tier
with no server.
"""

import inspect

from cache.semantic_cache import NO_POLICY, _cache_key, policy_identity
from services.gateway.service import GatewayService


def _identity(**overrides) -> str:
    """A complete, valid identity call with one field optionally changed."""
    base = {
        "block_threshold":             0.7,
        "sanitize_threshold":          0.4,
        "pii_block_threshold":         0.7,
        "pii_sanitize_threshold":      0.4,
        "toxicity_block_threshold":    0.7,
        "toxicity_sanitize_threshold": 0.4,
        "rule_enabled":                True,
        "ml_enabled":                  True,
        "llm_enabled":                 True,
        "llm_settings":                {"provider": "ollama", "model": "m"},
    }
    base.update(overrides)
    return policy_identity(**base)


# ── the drift guard ──────────────────────────────────────────────────────────

def test_identity_covers_every_decision_input_of_the_pipeline():
    """
    `policy_identity`'s parameters must be exactly the policy-derived arguments
    of `GatewayService.process`. Those arguments ARE the decision inputs, so
    two requests agreeing on all of them are judged identically and may share a
    verdict; one that is missing lets a policy difference go unrepresented in
    the key, which is the defect this key exists to close.

    This fails when a new decision input is added to the pipeline without being
    accounted for in the key -- the failure mode that cannot be caught by a test
    of the behaviour that exists today.
    """
    process_params  = list(inspect.signature(GatewayService.process).parameters)
    identity_params = set(inspect.signature(policy_identity).parameters)

    # `self` and `request` are not policy; everything after them is.
    policy_derived = set(process_params) - {"self", "request"}

    missing = policy_derived - identity_params
    assert not missing, (
        "GatewayService.process takes decision input(s) the cache key does not "
        f"represent: {sorted(missing)}. A cached verdict could be reused across "
        "a policy difference in those fields. Add them to policy_identity."
    )

    extra = identity_params - policy_derived
    assert not extra, (
        f"policy_identity takes {sorted(extra)}, which no longer reach "
        "GatewayService.process. Remove them, or the key over-invalidates."
    )


# ── policy identity ──────────────────────────────────────────────────────────

def test_same_policy_gives_the_same_identity():
    assert _identity() == _identity()


def test_every_decision_input_changes_the_identity():
    """
    Each field independently. A field that is accepted but not hashed would be
    invisible here and would let two different policies share an entry.
    """
    baseline = _identity()
    for field, altered in [
        ("block_threshold",             0.9),
        ("sanitize_threshold",          0.1),
        ("pii_block_threshold",         0.9),
        ("pii_sanitize_threshold",      0.1),
        ("toxicity_block_threshold",    0.9),
        ("toxicity_sanitize_threshold", 0.1),
        ("rule_enabled",                False),
        ("ml_enabled",                  False),
        ("llm_enabled",                 False),
        ("llm_settings",                {"provider": "openai", "model": "m"}),
    ]:
        assert _identity(**{field: altered}) != baseline, (
            f"{field} does not affect the cache key; two policies differing "
            f"only in it would share a cached verdict"
        )


def test_provider_credentials_do_not_affect_the_identity():
    """
    A credential cannot change a verdict, and rotating one must not discard the
    tenant's cache. It is also not something to feed into a key derivation.
    """
    without = _identity(llm_settings={"provider": "openai", "model": "m"})
    with_a  = _identity(llm_settings={"provider": "openai", "model": "m",
                                      "api_key": "sk-aaa"})
    with_b  = _identity(llm_settings={"provider": "openai", "model": "m",
                                      "api_key": "sk-bbb"})
    assert without == with_a == with_b


def test_absent_policy_is_distinct_from_any_resolved_one():
    assert NO_POLICY != _identity()


# ── the key itself ───────────────────────────────────────────────────────────

def _key(**overrides) -> str:
    base = {
        "text":           "hello",
        "detection_mode": "fast",
        "execution_mode": "scan_only",
        "tenant_id":      "tenant-a",
        "policy_id":      _identity(),
        "input_source":   "user_prompt",
    }
    base.update(overrides)
    return _cache_key(**base)


def test_a_stricter_scope_cannot_read_another_scopes_verdict():
    """
    The regression. Same tenant, same prompt, same modes -- one department
    resolving to a lower block threshold. Before the policy identity was in the
    key these produced the same entry, and the stricter department was served
    the laxer one's ALLOW.
    """
    lax     = _key(policy_id=_identity(block_threshold=0.9))
    strict  = _key(policy_id=_identity(block_threshold=0.3))
    assert lax != strict


def test_disabling_a_detection_layer_does_not_reuse_the_old_verdict():
    full    = _key(policy_id=_identity())
    no_ml   = _key(policy_id=_identity(ml_enabled=False))
    assert full != no_ml


def test_provenance_is_part_of_the_key():
    """
    Source posture judges untrusted origins against lower thresholds, so the
    same text arriving as a retrieved document is not the same question as the
    user typing it.
    """
    assert _key(input_source="user_prompt") != _key(input_source="retrieved_document")


def test_tenant_is_still_part_of_the_key():
    assert _key(tenant_id="tenant-a") != _key(tenant_id="tenant-b")


def test_identical_requests_still_share_an_entry():
    """The cache must still work: nothing above should have made it useless."""
    assert _key() == _key()
