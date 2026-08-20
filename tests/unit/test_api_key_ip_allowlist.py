# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Managing the networks a credential may be used from.

The enforcement path is covered with the proxy; this covers the control surface:
who may change the restriction, what is accepted, what the change is recorded as,
and who may see it. A restriction an administrator can quietly remove is a weak
control, so the change itself is a recorded event.
"""

import uuid

import pytest

from api.v1.endpoints.keys import (
    CreateKeySchema,
    UpdateKeySchema,
    _record_allowlist_change,
)
from domain.enums import AdminEventAction


class TestWriteTimeValidation:
    """A malformed entry is refused while the operator can still fix it."""

    def test_a_valid_list_is_accepted_and_canonicalised(self):
        schema = CreateKeySchema(name="k", ip_allowlist=["10.0.0.5/24", "203.0.113.7"])
        assert schema.ip_allowlist == ["10.0.0.0/24", "203.0.113.7/32"]

    def test_omitted_means_unrestricted(self):
        assert CreateKeySchema(name="k").ip_allowlist is None

    def test_an_empty_list_means_unrestricted(self):
        assert CreateKeySchema(name="k", ip_allowlist=[]).ip_allowlist == []

    @pytest.mark.parametrize("bad", ["not-an-ip", "10.0.0.300", "10.0.0.0/99"])
    def test_a_malformed_entry_is_refused(self, bad):
        with pytest.raises(ValueError):
            CreateKeySchema(name="k", ip_allowlist=[bad])

    @pytest.mark.parametrize("everything", ["0.0.0.0/0", "::/0"])
    def test_a_list_covering_every_address_is_refused(self, everything):
        """
        Storing it would leave a credential that looks restricted and is not.
        Leave the list empty to permit everything, and mean it.
        """
        with pytest.raises(ValueError, match="not a restriction"):
            CreateKeySchema(name="k", ip_allowlist=[everything])

    def test_the_same_rules_apply_when_updating(self):
        assert UpdateKeySchema(name="k", ip_allowlist=["10.0.0.0/8"]).ip_allowlist == ["10.0.0.0/8"]
        with pytest.raises(ValueError):
            UpdateKeySchema(name="k", ip_allowlist=["nonsense"])
        with pytest.raises(ValueError, match="not a restriction"):
            UpdateKeySchema(name="k", ip_allowlist=["0.0.0.0/0"])


class TestChangeIsRecorded:
    """
    Whoever can set a restriction can also remove it, so the change is the
    security event. These exercise the recorder itself rather than restating its
    logic.
    """

    async def _record(self, previous, current):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, patch

        captured = {}

        async def _insert(**kwargs):
            captured.update(kwargs)

        request = SimpleNamespace(
            state   = SimpleNamespace(tenant_id=str(uuid.uuid4())),
            headers = {"user-agent": "test-agent"},
        )
        principal = SimpleNamespace(id=f"user:{uuid.uuid4()}")
        db        = AsyncMock()

        with (
            patch("api.v1.endpoints.keys.AdminEventRepository") as repo_cls,
            patch("api.v1.endpoints.keys.get_client_ip", return_value="203.0.113.9"),
        ):
            repo_cls.return_value.insert = _insert
            await _record_allowlist_change(
                db, request, principal, "wsk_abc", None,
                previous=previous, current=current,
            )
        return captured

    @pytest.mark.asyncio
    async def test_adding_a_restriction_is_recorded_as_added(self):
        captured = await self._record(None, ["10.0.0.0/8"])
        assert captured["action"] == AdminEventAction.KEY_ALLOWLIST_CHANGED
        assert captured["metadata"]["change"]  == "added"
        assert captured["metadata"]["current"] == ["10.0.0.0/8"]

    @pytest.mark.asyncio
    async def test_replacing_a_restriction_is_recorded_as_changed(self):
        captured = await self._record(["10.0.0.0/8"], ["192.0.2.0/24"])
        assert captured["metadata"]["change"]   == "changed"
        assert captured["metadata"]["previous"] == ["10.0.0.0/8"]
        assert captured["metadata"]["current"]  == ["192.0.2.0/24"]

    @pytest.mark.asyncio
    async def test_removing_a_restriction_is_recorded_as_removed(self):
        """The act that most needs a trail: the control being switched off."""
        captured = await self._record(["10.0.0.0/8"], [])
        assert captured["metadata"]["change"]  == "removed"
        assert captured["metadata"]["current"] == []

    @pytest.mark.asyncio
    async def test_resaving_the_same_restriction_records_nothing(self):
        """Re-saving an unchanged list is not a change to the boundary."""
        captured = await self._record(["10.0.0.0/8"], ["10.0.0.0/8"])
        assert captured == {}

    @pytest.mark.asyncio
    async def test_the_event_carries_context_but_never_the_secret(self):
        captured = await self._record(None, ["10.0.0.0/8"])
        assert captured["metadata"]["key_id"] == "wsk_abc"
        assert captured["ip_address"]         == "203.0.113.9"
        assert captured["user_agent"]         == "test-agent"
        serialised = str(captured)
        assert "key_hash"  not in serialised
        assert "wsk_live_" not in serialised
