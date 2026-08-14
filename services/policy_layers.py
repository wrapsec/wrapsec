# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Policy-layer hook -- the plan/entitlement seam (Phase 2, 2.9 / open-core P4).

resolve_policy() computes the effective policy from the core layers (system
defaults -> platform/tenant settings -> department -> application). This module
lets a plugin register additional layers that run as a FINAL CEILING, after all
core resolution: a billing/entitlement plugin registers a layer that clamps the
resolved policy by tenants.plan (e.g. a Free plan caps rate_limit.per_minute or
disables the LLM detector), and that cap wins over a tenant admin's app override
-- which is exactly why it runs last.

The core never interprets tenants.plan; it only provides the seam. In the OSS
edition no layer is registered, so resolve_policy skips this entirely and its
output is byte-identical to before this hook existed.

Contract:
  - A layer is an async callable (policy: dict, context: PolicyContext) -> dict.
    It returns the (possibly modified) policy; returning a non-dict is ignored.
  - Layers run in registration order.
  - FAIL-OPEN: a layer that raises is logged and skipped -- a plan-layer bug must
    never break policy resolution (matching resolve_policy's own error posture).
    A ceiling that silently no-ops is the safe failure for a security gateway;
    the request still gets the core-resolved policy.
  - This is policy shaping, never authorization.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("wrapsec.policy")


@dataclass(frozen=True)
class PolicyContext:
    """What a policy layer needs to resolve a plan/entitlement decision. Carries
    the request's identity scope and the live DB session so a layer can read
    tenants.plan or a plugin-owned entitlement table."""
    db:        Any
    tenant_id: str | None
    dept_id:   str | None
    app_id:    str | None


PolicyLayer = Callable[[dict, "PolicyContext"], Awaitable[dict]]

_LAYERS: list[PolicyLayer] = []


def register_policy_layer(layer: PolicyLayer) -> None:
    """Append a policy layer, run as a final ceiling after core resolution.
    Called by a plugin's register(app). The OSS core registers none."""
    _LAYERS.append(layer)


def registered_policy_layers() -> list[PolicyLayer]:
    """The layers currently registered (registration order). Empty in OSS."""
    return list(_LAYERS)


async def apply_policy_layers(policy: dict, context: PolicyContext) -> dict:
    """
    Run every registered layer in order, threading the policy through each.
    No-op (returns policy unchanged) when nothing is registered. A layer that
    raises is logged and skipped so resolution always yields a usable policy.
    """
    for layer in _LAYERS:
        try:
            result = await layer(policy, context)
            if isinstance(result, dict):
                policy = result
        except Exception as e:
            logger.warning(
                "policy layer %r failed, skipping: %s",
                getattr(layer, "__name__", layer), e,
            )
    return policy
