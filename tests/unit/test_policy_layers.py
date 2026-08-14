# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Policy-layer hook (Phase 2, 2.9) -- pure unit coverage of the registry and the
fail-open apply loop. The end-to-end proof that resolve_policy threads the
resolved policy through a plugin layer lives in
tests/integration/test_refplugin.py::test_policy_layer_registration_seam.
"""
import pytest

import services.policy_layers as pl
from services.policy_layers import (
    PolicyContext,
    apply_policy_layers,
    register_policy_layer,
    registered_policy_layers,
)


def _ctx():
    return PolicyContext(db=None, tenant_id="t", dept_id=None, app_id=None)


@pytest.mark.asyncio
async def test_no_layers_is_identity():
    assert registered_policy_layers() == []
    policy = {"rate_limit": {"per_minute": 60}, "thresholds": {"block": 0.7}}
    out = await apply_policy_layers(policy, _ctx())
    assert out == policy


@pytest.mark.asyncio
async def test_layers_run_in_registration_order():
    async def add_a(policy, ctx):
        return {**policy, "trace": policy.get("trace", "") + "a"}

    async def add_b(policy, ctx):
        return {**policy, "trace": policy.get("trace", "") + "b"}

    before = list(pl._LAYERS)
    register_policy_layer(add_a)
    register_policy_layer(add_b)
    try:
        out = await apply_policy_layers({}, _ctx())
        assert out["trace"] == "ab"
    finally:
        pl._LAYERS[:] = before


@pytest.mark.asyncio
async def test_failing_layer_is_skipped_fail_open():
    async def boom(policy, ctx):
        raise RuntimeError("plan lookup failed")

    before = list(pl._LAYERS)
    register_policy_layer(boom)
    try:
        out = await apply_policy_layers({"rate_limit": {"per_minute": 60}}, _ctx())
        assert out == {"rate_limit": {"per_minute": 60}}   # unchanged, not raised
    finally:
        pl._LAYERS[:] = before


@pytest.mark.asyncio
async def test_non_dict_return_is_ignored():
    async def bad(policy, ctx):
        return None            # a misbehaving layer

    before = list(pl._LAYERS)
    register_policy_layer(bad)
    try:
        out = await apply_policy_layers({"x": 1}, _ctx())
        assert out == {"x": 1}
    finally:
        pl._LAYERS[:] = before
