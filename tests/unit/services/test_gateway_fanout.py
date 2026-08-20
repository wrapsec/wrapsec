# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Fan-out behaviour shared by every caller that scans several inputs at once.

These pin the properties that are easy to lose in a refactor and expensive to
lose in production: the rate-limit charge excludes the slot the HTTP request
already consumed, results come back in request order, concurrency stays bounded,
and each input keeps its own trust source.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from domain.entities.request import RequestMetadata
from domain.enums import DetectionMode
from errors.exceptions import RateLimitError
from services.gateway.fanout import (
    DetectionPolicy,
    ScanItem,
    charge_additional_units,
    scan_items,
)


def _request(key_id: str | None = "k1"):
    return SimpleNamespace(state=SimpleNamespace(key_id=key_id, ip_address="1.2.3.4"))


def _policy():
    return DetectionPolicy(block_threshold=0.7, sanitize_threshold=0.4)


class _FakeGateway:
    """Records the requests it was handed and how many ran at once."""

    def __init__(self, delay: float = 0.0):
        self.seen        = []
        self.delay       = delay
        self.concurrent  = 0
        self.max_concurrent = 0

    async def process(self, incoming, *args, **kwargs):
        self.concurrent += 1
        self.max_concurrent = max(self.max_concurrent, self.concurrent)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            self.seen.append(incoming)
            return SimpleNamespace(decision=SimpleNamespace(input=incoming.input))
        finally:
            self.concurrent -= 1


# ── Rate-limit accounting ─────────────────────────────────────────────────────

class TestChargeAdditionalUnits:

    @pytest.mark.asyncio
    async def test_single_input_charges_nothing(self):
        """One input is already paid for by the HTTP request itself."""
        with patch("cache.rate_limit_store.is_rate_limited", new=AsyncMock()) as m:
            await charge_additional_units(_request(), 1)
        m.assert_not_called()

    @pytest.mark.asyncio
    async def test_charges_n_minus_one(self):
        """N inputs cost N units total, one of which was already consumed."""
        mock = AsyncMock(return_value=(False, 0, 0))
        with patch("cache.rate_limit_store.is_rate_limited", new=mock):
            await charge_additional_units(_request(), 5)

        assert mock.await_args.kwargs["cost"] == 4
        assert mock.await_args.args[0] == "key:k1"

    @pytest.mark.asyncio
    async def test_falls_back_to_ip_without_a_key(self):
        mock = AsyncMock(return_value=(False, 0, 0))
        with patch("cache.rate_limit_store.is_rate_limited", new=mock):
            await charge_additional_units(_request(key_id=None), 3)

        assert mock.await_args.args[0] == "ip:1.2.3.4"

    @pytest.mark.asyncio
    async def test_raises_when_the_bucket_is_exhausted(self):
        mock = AsyncMock(return_value=(True, 0, 0))
        with (
            patch("cache.rate_limit_store.is_rate_limited", new=mock),
            pytest.raises(RateLimitError),
        ):
            await charge_additional_units(_request(), 4)

    @pytest.mark.asyncio
    async def test_fails_open_when_the_store_is_unavailable(self):
        """A limiter outage must not deny traffic."""
        mock = AsyncMock(side_effect=RuntimeError("redis down"))
        with patch("cache.rate_limit_store.is_rate_limited", new=mock):
            await charge_additional_units(_request(), 4)  # must not raise


# ── Fan-out ───────────────────────────────────────────────────────────────────

class TestScanItems:

    @pytest.mark.asyncio
    async def test_results_follow_input_order(self):
        """Order comes from the input list, never from completion time."""
        gateway = _FakeGateway()
        items   = [ScanItem(input=f"m{i}", input_source="user_prompt") for i in range(6)]

        out = await scan_items(
            items,
            gateway        = gateway,  # type: ignore[arg-type]
            policy         = _policy(),
            detection_mode = DetectionMode.FAST,
            metadata       = RequestMetadata(tenant_id="t1"),
        )

        assert [inc.input for inc, _ in out] == [f"m{i}" for i in range(6)]

    @pytest.mark.asyncio
    async def test_each_item_keeps_its_own_source(self):
        """
        Mixed-trust conversations depend on this: a joined classification would
        stamp one trust level onto content the caller did not author.
        """
        gateway = _FakeGateway()
        items   = [
            ScanItem(input="a", input_source="user_prompt"),
            ScanItem(input="b", input_source="external_content"),
            ScanItem(input="c", input_source="user_prompt"),
        ]

        out = await scan_items(
            items,
            gateway        = gateway,  # type: ignore[arg-type]
            policy         = _policy(),
            detection_mode = DetectionMode.FAST,
            metadata       = RequestMetadata(tenant_id="t1"),
        )

        assert [inc.input_source for inc, _ in out] == [
            "user_prompt", "external_content", "user_prompt",
        ]

    @pytest.mark.asyncio
    async def test_concurrency_is_bounded(self):
        """One request must not launch unbounded detector work."""
        gateway = _FakeGateway(delay=0.01)
        items   = [ScanItem(input=f"m{i}", input_source="user_prompt") for i in range(12)]

        await scan_items(
            items,
            gateway        = gateway,  # type: ignore[arg-type]
            policy         = _policy(),
            detection_mode = DetectionMode.FAST,
            metadata       = RequestMetadata(tenant_id="t1"),
            concurrency    = 3,
        )

        assert gateway.max_concurrent <= 3

    @pytest.mark.asyncio
    async def test_supplied_trace_id_is_used_and_absent_one_is_generated(self):
        """
        A caller writing several audit rows for one request must be able to hand
        in distinct ids, because the audit trace column is unique.
        """
        gateway = _FakeGateway()
        items   = [
            ScanItem(input="a", input_source="user_prompt", trace_id="req_abcdefghijklmnopqrst-0"),
            ScanItem(input="b", input_source="user_prompt"),
        ]

        out = await scan_items(
            items,
            gateway        = gateway,  # type: ignore[arg-type]
            policy         = _policy(),
            detection_mode = DetectionMode.FAST,
            metadata       = RequestMetadata(tenant_id="t1"),
        )

        assert str(out[0][0].trace_id) == "req_abcdefghijklmnopqrst-0"
        generated = str(out[1][0].trace_id)
        assert generated.startswith("req_")
        assert generated != str(out[0][0].trace_id)
