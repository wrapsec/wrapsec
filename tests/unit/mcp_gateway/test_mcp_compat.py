# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The SDK seam must detect a changed MCP package and refuse to start.

These tests do not assert that the code contains a check. They REMOVE and ALTER
the APIs the gateway depends on and assert the probe notices, because a
fail-closed path that has never been made to fail is an assumption, not a
control.

The `allow_input_required` case is the sharpest one. That flag is what keeps the
modern sampling and elicitation channel closed: with it `False`, a downstream
server returning an `InputRequiredResult` raises instead of handing
server-authored content to the agent. If a future SDK flips the default, the
gateway must refuse to start rather than quietly begin forwarding it.
"""

from __future__ import annotations

import inspect

import pytest

from mcp_gateway.mcp_compat import (
    SUPPORTED_MCP_VERSION,
    UnsupportedMCPPackage,
    _missing_apis,
    installed_mcp_version,
    verify_mcp_package,
)


def test_the_pinned_version_is_what_is_installed():
    """The seam is only meaningful if the environment matches the pin."""
    assert installed_mcp_version() == SUPPORTED_MCP_VERSION, (
        f"installed {installed_mcp_version()}, pinned {SUPPORTED_MCP_VERSION}; "
        f"re-verify the API surface before trusting these tests"
    )


def test_every_required_api_is_present_at_the_pin():
    """A real probe of the installed package, not a version-string comparison."""
    assert _missing_apis() == []


def test_verification_passes_at_the_pin():
    verify_mcp_package()          # must not raise


# ---------------------------------------------------------------------------
# the probe must actually bite
# ---------------------------------------------------------------------------

def test_a_removed_server_hook_is_detected(monkeypatch):
    """Drop `on_call_tool` from the Server constructor and the probe must say so."""
    from mcp.server.lowlevel import Server

    original = Server.__init__

    def _without_on_call_tool(self, name, *, version="", **kwargs):
        kwargs.pop("on_call_tool", None)
        return original(self, name, version=version, **kwargs)

    # Rebuild a signature that no longer advertises the hook.
    params = [
        p for p in inspect.signature(original).parameters.values()
        if p.name != "on_call_tool"
    ]
    _without_on_call_tool.__signature__ = inspect.Signature(params)
    monkeypatch.setattr(Server, "__init__", _without_on_call_tool)

    assert any("on_call_tool" in m for m in _missing_apis())
    with pytest.raises(UnsupportedMCPPackage, match="on_call_tool"):
        verify_mcp_package()


def test_a_removed_input_required_guard_is_detected(monkeypatch):
    """If `allow_input_required` disappears, the modern channel is open by
    default and the gateway must not start."""
    from mcp.client.session import ClientSession

    original = ClientSession.call_tool
    params   = [
        p for p in inspect.signature(original).parameters.values()
        if p.name != "allow_input_required"
    ]

    async def _without_guard(self, *args, **kwargs):  # pragma: no cover - never called
        raise AssertionError("not invoked")

    _without_guard.__signature__ = inspect.Signature(params)
    monkeypatch.setattr(ClientSession, "call_tool", _without_guard)

    assert any("allow_input_required" in m for m in _missing_apis())
    with pytest.raises(UnsupportedMCPPackage, match="allow_input_required"):
        verify_mcp_package()


def test_a_flipped_input_required_default_is_detected(monkeypatch):
    """The subtle one: the parameter still exists, but now defaults to True.

    Nothing would raise, nothing would look broken, and every
    `InputRequiredResult` would flow to the agent. The probe checks the DEFAULT,
    not merely the presence of the name.
    """
    from mcp.client.session import ClientSession

    original = ClientSession.call_tool
    params   = [
        p.replace(default=True) if p.name == "allow_input_required" else p
        for p in inspect.signature(original).parameters.values()
    ]

    async def _flipped(self, *args, **kwargs):  # pragma: no cover - never called
        raise AssertionError("not invoked")

    _flipped.__signature__ = inspect.Signature(params)
    monkeypatch.setattr(ClientSession, "call_tool", _flipped)

    missing = _missing_apis()
    assert any("no longer defaults to False" in m for m in missing), missing
    with pytest.raises(UnsupportedMCPPackage):
        verify_mcp_package()


def test_a_removed_claimed_guard_is_detected(monkeypatch):
    """The same protection for the claimed-result channel.

    This one was pinned late. `allow_input_required` was checked from the start
    and `allow_claimed` was not, so the probe verified one of the two channels
    that must stay shut and reported the package sound. A guard that covers only
    the channel you remembered is the failure it was meant to prevent.
    """
    from mcp.client.session import ClientSession

    original = ClientSession.call_tool
    params   = [
        p for p in inspect.signature(original).parameters.values()
        if p.name != "allow_claimed"
    ]

    async def _without_guard(self, *args, **kwargs):  # pragma: no cover - never called
        raise AssertionError("not invoked")

    _without_guard.__signature__ = inspect.Signature(params)
    monkeypatch.setattr(ClientSession, "call_tool", _without_guard)

    assert any("allow_claimed" in m for m in _missing_apis())
    with pytest.raises(UnsupportedMCPPackage, match="allow_claimed"):
        verify_mcp_package()


def test_a_flipped_claimed_default_is_detected(monkeypatch):
    """Still present, now defaulting to True: every claimed result would be
    RETURNED rather than refused, carrying an extension payload the gateway has
    no handler for and therefore never judged."""
    from mcp.client.session import ClientSession

    original = ClientSession.call_tool
    params   = [
        p.replace(default=True) if p.name == "allow_claimed" else p
        for p in inspect.signature(original).parameters.values()
    ]

    async def _flipped(self, *args, **kwargs):  # pragma: no cover - never called
        raise AssertionError("not invoked")

    _flipped.__signature__ = inspect.Signature(params)
    monkeypatch.setattr(ClientSession, "call_tool", _flipped)

    missing = _missing_apis()
    assert any("allow_claimed" in m and "no longer defaults to False" in m
               for m in missing), missing
    with pytest.raises(UnsupportedMCPPackage):
        verify_mcp_package()


# ---------------------------------------------------------------------------
# the hand-copied tool-name rule must not drift from the SDK's
# ---------------------------------------------------------------------------

def test_the_gateway_tool_name_rule_is_no_laxer_than_the_sdk_rule():
    """`routing.py` carries its own copy of the SEP-986 pattern.

    Keeping a local copy is deliberate: the SDK's own check is advisory, and a
    security gateway should not have its published-name rule loosened by a
    dependency upgrade. But a hand-copied pattern can drift, so this asserts the
    local rule accepts nothing the SDK's rule rejects.
    """
    from mcp.shared.tool_name_validation import TOOL_NAME_REGEX

    from mcp_gateway.routing import _CONFORMING_TOOL_NAME

    samples = [
        "read_file", "read-file", "read.file", "a", "A1._-",
        "read__raw", "x" * 128,
        "a/b", "a b", "a,b", "", "x" * 129, "unicode\u00e9", "tab\there",
    ]
    for sample in samples:
        sdk_ok   = bool(TOOL_NAME_REGEX.match(sample))
        local_ok = bool(_CONFORMING_TOOL_NAME.match(sample))
        if local_ok:
            assert sdk_ok, (
                f"the gateway would publish {sample!r}, which the SDK's own rule "
                f"rejects; the local pattern has drifted looser"
            )
