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

from config.settings import get_settings
from domain.entities.request import RequestMetadata
from domain.enums import DetectionMode
from errors.exceptions import RateLimitError
from services.gateway.fanout import (
    DetectionPolicy,
    ScanItem,
    charge_additional_units,
    scan_items,
)


def _request(key_id: str | None = "k1", rate_limit_id: str | None = "key:abc123def456"):
    """
    The state a request carries by the time the fan-out runs.

    rate_limit_id is what the enforcing limiter published. It is deliberately
    NOT derived from key_id: the two are different values, and a fixture that
    made them look related is how the divergence stayed invisible.
    """
    return SimpleNamespace(state=SimpleNamespace(
        key_id=key_id, ip_address="1.2.3.4", rate_limit_id=rate_limit_id,
    ))


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
        # the bucket the limiter enforces, not one derived here
        assert mock.await_args.args[0] == "key:abc123def456"

    @pytest.mark.asyncio
    async def test_it_charges_whatever_the_limiter_bucketed_on(self):
        """
        Including the anonymous case. The fan-out does not decide the bucket; it
        reuses the one already in force, so a JWT or anonymous request charges
        the address bucket without the fan-out knowing that is why.
        """
        mock = AsyncMock(return_value=(False, 0, 0))
        with patch("cache.rate_limit_store.is_rate_limited", new=mock):
            await charge_additional_units(
                _request(key_id=None, rate_limit_id="ip:1.2.3.4"), 3,
            )

        assert mock.await_args.args[0] == "ip:1.2.3.4"

    @pytest.mark.asyncio
    async def test_it_does_not_invent_a_bucket_from_the_key_id(self):
        """
        The defect this replaced: the fan-out built its own identifier from
        request.state.key_id, which is the key record's id and already carries a
        "key:" prefix. That produced "key:key:..." -- a bucket nothing reads, so
        the extra units were charged nowhere and the fan-out was unmetered.
        """
        mock = AsyncMock(return_value=(False, 0, 0))
        with patch("cache.rate_limit_store.is_rate_limited", new=mock):
            await charge_additional_units(
                _request(key_id="key:key_abc123", rate_limit_id="key:abc123def456"), 4,
            )

        charged = mock.await_args.args[0]
        assert charged == "key:abc123def456"
        assert "key_abc123" not in charged, "the bucket was derived from key_id"
        assert not charged.startswith("key:key:"), "double-prefixed bucket"

    @pytest.mark.asyncio
    async def test_a_missing_identifier_charges_nothing_and_is_loud(self, caplog):
        """
        The limiter runs ahead of every path that reaches here, so an absent
        identifier means the contract broke. Silently skipping would make the
        fan-out unmetered again, with nothing to notice it by.
        """
        state   = SimpleNamespace(key_id="k1", ip_address="1.2.3.4")
        request = SimpleNamespace(state=state)   # no rate_limit_id at all

        mock = AsyncMock(return_value=(False, 0, 0))
        with (
            patch("cache.rate_limit_store.is_rate_limited", new=mock),
            caplog.at_level("ERROR"),
        ):
            await charge_additional_units(request, 5)

        mock.assert_not_called()
        assert any("rate-limit identifier" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_an_inapplicable_limiter_charges_nothing_quietly(self, caplog):
        """
        None is the limiter saying it did not run -- limiting disabled, or a path
        it does not cover. Nothing to charge, and nothing worth logging about.
        """
        mock = AsyncMock(return_value=(False, 0, 0))
        with (
            patch("cache.rate_limit_store.is_rate_limited", new=mock),
            caplog.at_level("ERROR"),
        ):
            await charge_additional_units(_request(rate_limit_id=None), 5)

        mock.assert_not_called()
        assert not caplog.records

    @pytest.mark.asyncio
    async def test_a_programming_error_is_not_swallowed(self):
        """
        The handler that used to sit here caught every exception and discarded
        it, which is what hid the wrong-bucket defect. The store already fails
        open on its own outages, so there is nothing left for a broad catch to
        absorb except the caller's own mistakes.
        """
        with (
            patch("cache.rate_limit_store.is_rate_limited",
                  new=AsyncMock(side_effect=TypeError("signature changed"))),
            pytest.raises(TypeError),
        ):
            await charge_additional_units(_request(), 5)

    @pytest.mark.asyncio
    async def test_raises_when_the_bucket_is_exhausted(self):
        mock = AsyncMock(return_value=(True, 0, 0))
        with (
            patch("cache.rate_limit_store.is_rate_limited", new=mock),
            pytest.raises(RateLimitError),
        ):
            await charge_additional_units(_request(), 4)

    @pytest.mark.asyncio
    async def test_a_store_outage_does_not_deny_traffic(self):
        """
        A limiter outage must not deny traffic -- but that is the STORE's
        responsibility, not this function's. is_rate_limited catches its own
        failures and returns "not limited", so the outage never reaches here.

        Asserted through that contract rather than by making the store raise:
        a broad catch here to absorb an exception the store does not throw is
        what hid the wrong-bucket defect for as long as it existed.
        """
        outage = AsyncMock(return_value=(False, get_settings().rate_limit_per_minute, 0))
        with patch("cache.rate_limit_store.is_rate_limited", new=outage):
            await charge_additional_units(_request(), 4)  # must not raise
        outage.assert_awaited_once()


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


class TestProcessWideBound:
    """
    The bound has to hold ACROSS concurrent calls, not just within one.

    A semaphore built per call bounds only the call that built it, so N
    concurrent multi-input requests ran up to N times the limit between them.
    That is not an efficiency question: detection is fail-closed, so detectors
    pushed past their timeout produce BLOCKs that the caller cannot tell from a
    decision about their content.
    """

    @staticmethod
    async def _run(gateway, items, **kwargs):
        return await scan_items(
            [ScanItem(input=f"m{i}", input_source="user_prompt") for i in range(items)],
            gateway        = gateway,
            policy         = _policy(),
            detection_mode = DetectionMode.FAST,
            metadata       = RequestMetadata(tenant_id="t"),
            **kwargs,
        )

    @pytest.mark.asyncio
    async def test_concurrent_calls_share_one_bound(self, monkeypatch):
        monkeypatch.setenv("BATCH_CONCURRENCY", "4")
        get_settings.cache_clear()
        try:
            gateway = _FakeGateway(delay=0.02)
            # Four calls of five items each. Per-call bounding would allow up to
            # sixteen at once; the process-wide bound allows four.
            await asyncio.gather(*[self._run(gateway, 5) for _ in range(4)])
            assert gateway.max_concurrent <= 4, (
                f"{gateway.max_concurrent} detector runs at once against a bound of 4"
            )
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_the_bound_is_actually_reached(self, monkeypatch):
        """
        The counterpart. A bound that is never reached would make the test above
        pass even if the work were running one at a time.
        """
        monkeypatch.setenv("BATCH_CONCURRENCY", "4")
        get_settings.cache_clear()
        try:
            gateway = _FakeGateway(delay=0.02)
            await asyncio.gather(*[self._run(gateway, 5) for _ in range(4)])
            assert gateway.max_concurrent == 4, (
                f"only {gateway.max_concurrent} ran at once; the bound is not the limit"
            )
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_a_caller_cannot_buy_more_capacity(self, monkeypatch):
        """
        The per-call argument tightens; it must not loosen. Otherwise a caller
        escapes the process bound by asking for a bigger one.
        """
        monkeypatch.setenv("BATCH_CONCURRENCY", "2")
        get_settings.cache_clear()
        try:
            gateway = _FakeGateway(delay=0.02)
            await asyncio.gather(*[
                self._run(gateway, 6, concurrency=50) for _ in range(3)
            ])
            assert gateway.max_concurrent <= 2, (
                f"a caller-supplied concurrency of 50 ran {gateway.max_concurrent} at once"
            )
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_a_tighter_per_call_bound_still_applies(self, monkeypatch):
        monkeypatch.setenv("BATCH_CONCURRENCY", "8")
        get_settings.cache_clear()
        try:
            gateway = _FakeGateway(delay=0.02)
            await self._run(gateway, 6, concurrency=2)
            assert gateway.max_concurrent <= 2
        finally:
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_a_changed_limit_is_picked_up(self, monkeypatch):
        """
        The limit is a setting. A cached semaphore keyed only by loop would keep
        the old capacity after it changed, which is the failure mode of caching
        a value derived from configuration.
        """
        gateway = _FakeGateway(delay=0.02)

        monkeypatch.setenv("BATCH_CONCURRENCY", "2")
        get_settings.cache_clear()
        await asyncio.gather(*[self._run(gateway, 4) for _ in range(3)])
        assert gateway.max_concurrent <= 2

        gateway.max_concurrent = 0
        monkeypatch.setenv("BATCH_CONCURRENCY", "6")
        get_settings.cache_clear()
        try:
            await asyncio.gather(*[self._run(gateway, 4) for _ in range(3)])
            assert gateway.max_concurrent > 2, "still bounded by the previous limit"
        finally:
            get_settings.cache_clear()
