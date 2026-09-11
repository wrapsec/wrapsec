# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Routing must not be influenced by anything a downstream server chooses.

A downstream tool name is unconstrained: `Tool.name` is a bare string with no
pattern and no length limit, the SDK's charset rule is advisory and never applied
to names arriving from `tools/list`, and underscore is a permitted character so
`__` is legal inside a name. Every test here exists because of that.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from mcp_gateway.config import ConfigError, GatewayConfig, ServerConfig, ToolPolicy
from mcp_gateway.routing import (
    RoutingError,
    RoutingTable,
    assert_no_cross_server_shadowing,
    exposed_name,
)


@dataclass
class _Tool:
    """Stands in for an MCP Tool; only `name` matters to routing."""

    name: str


class _Session:
    def __init__(self, label: str) -> None:
        self.label = label


def _config(*names: str) -> GatewayConfig:
    return GatewayConfig(
        servers=tuple(ServerConfig(name=n, command=("echo",)) for n in names)
    )


# ---------------------------------------------------------------------------
# resolution is exact -- never parsed
# ---------------------------------------------------------------------------

def test_a_tool_name_containing_the_separator_still_routes_correctly():
    """`__` inside a downstream tool name must not confuse resolution.

    This is the case that rules out splitting the exposed name: `files` +
    `read__raw` and a hypothetical server `files__read` + `raw` would produce the
    same string if the separator were treated as a delimiter to parse.
    """
    session = _Session("files")
    table   = RoutingTable[_Session]()
    table.add_server("files", session, [_Tool("read__raw")])

    entry = table.resolve("files__read__raw")
    assert entry is not None, "a legal tool name containing the separator was lost"
    assert entry.server_name   == "files"
    assert entry.original_name == "read__raw", (
        "the gateway must call downstream with the ORIGINAL name, not a "
        "reconstructed one"
    )
    assert entry.session is session


def test_resolution_does_not_fall_back_to_prefix_matching():
    """A miss is a miss. No stripping, no substring search, no cross-server scan."""
    table = RoutingTable[_Session]()
    table.add_server("files", _Session("files"), [_Tool("read")])

    for miss in ("read", "files__", "files__read_file", "FILES__read", "files__read "):
        assert table.resolve(miss) is None, (
            f"{miss!r} resolved; resolution must be an exact lookup"
        )


def test_the_original_name_is_what_goes_downstream():
    """The namespace is a local construct and must never leave the gateway."""
    table = RoutingTable[_Session]()
    table.add_server("srv", _Session("srv"), [_Tool("weird name/with spaces")])
    # That name cannot be published (see rejection tests), so nothing routes.
    assert table.resolve(exposed_name("srv", "weird name/with spaces")) is None
    assert table.rejected and table.rejected[0].raw_name == "weird name/with spaces"


# ---------------------------------------------------------------------------
# rejection rather than repair
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "a/b",             # slash
    "a b",             # space
    "tab\there",       # control whitespace
    "unicode\u00e9",     # non-ASCII, written as an escape to keep the source ASCII
])
def test_a_nonconforming_name_is_rejected_not_escaped(bad):
    """Escaping would need to be reversible, and a reversible encoding over an
    attacker-controlled string is a parser. Reject instead."""
    table = RoutingTable[_Session]()
    table.add_server("srv", _Session("srv"), [_Tool(bad)])

    assert len(table) == 0, f"{bad!r} was published"
    assert table.rejected[0].raw_name == bad


def test_an_over_length_name_is_rejected_not_truncated():
    """Truncation manufactures collisions: two long names sharing a prefix would
    truncate to the same key."""
    table = RoutingTable[_Session]()
    table.add_server("srv", _Session("srv"), [_Tool("x" * 200)])

    assert len(table) == 0
    assert "over the" in table.rejected[0].reason


def test_a_second_tool_composing_to_a_taken_name_is_rejected():
    """The later one is refused; the first is not silently replaced."""
    first, second = _Session("a"), _Session("b")
    table = RoutingTable[_Session]()
    table.add_server("srv", first,  [_Tool("tool")])
    table.add_server("srv", second, [_Tool("tool")])

    assert len(table) == 1
    assert table.resolve("srv__tool").session is first, "the first registration lost"
    assert "already published" in table.rejected[0].reason


# ---------------------------------------------------------------------------
# impersonation
# ---------------------------------------------------------------------------

def test_a_tool_impersonating_another_servers_namespace_refuses_startup():
    """The concrete attack.

    A server configured as `evil` publishes a tool literally named
    `filesystem__read_file`. Routing resolves it correctly, because lookup is
    exact -- but the published name READS as belonging to `filesystem`, and an
    operator auditing the tool list should not have to know that only the first
    separator counts.
    """
    config = _config("filesystem", "evil")
    table  = RoutingTable[_Session]()
    table.add_server("filesystem", _Session("fs"),   [_Tool("read_file")])
    table.add_server("evil",       _Session("evil"), [_Tool("filesystem__read_file")])

    # It routes to the right place -- exact lookup is not fooled ...
    entry = table.resolve("evil__filesystem__read_file")
    assert entry is not None and entry.server_name == "evil"

    # ... and the gateway still refuses to start, because the NAME misattributes.
    with pytest.raises(RoutingError, match="reads as belonging to"):
        assert_no_cross_server_shadowing(table, config)


def test_a_separator_name_that_matches_no_configured_server_is_allowed():
    """Only impersonation of a CONFIGURED server is a problem; `__` on its own is
    ordinary and must not block startup."""
    config = _config("files")
    table  = RoutingTable[_Session]()
    table.add_server("files", _Session("files"), [_Tool("read__raw")])

    assert_no_cross_server_shadowing(table, config)   # does not raise


# ---------------------------------------------------------------------------
# configuration invariants that routing depends on
# ---------------------------------------------------------------------------

def test_a_server_name_containing_the_separator_is_refused():
    """The prefix must not be able to contain `__`, or the published name would
    be ambiguous to read even though lookup stays exact."""
    with pytest.raises(ConfigError, match="namespace prefix"):
        ServerConfig(name="bad__name", command=("echo",))


def test_duplicate_server_names_are_refused():
    with pytest.raises(ConfigError, match="more than once"):
        GatewayConfig(servers=(
            ServerConfig(name="dup", command=("echo",)),
            ServerConfig(name="dup", command=("echo",)),
        ))


def test_a_bare_policy_entry_is_refused_when_several_servers_exist():
    """A permission that silently matched a tool on another server would be a
    privilege bug wearing a typo."""
    with pytest.raises(ConfigError, match="Use b__read_file|is not"):
        GatewayConfig(servers=(
            ServerConfig(name="a", command=("echo",), tools=ToolPolicy(allow=("read_file",))),
            ServerConfig(name="b", command=("echo",)),
        ))


def test_a_bare_policy_entry_is_accepted_with_exactly_one_server():
    """The one case where it cannot be ambiguous."""
    config = GatewayConfig(servers=(
        ServerConfig(name="only", command=("echo",), tools=ToolPolicy(allow=("read_file",))),
    ))
    assert config.by_name("only") is not None


def test_the_impersonation_check_is_not_order_dependent():
    """It compares against the full configured set, whichever order servers
    registered in.

    An order-dependent check would pass or fail depending on configuration file
    ordering, which is not something a security control may depend on.
    """
    config = _config("filesystem", "evil")

    for first, second in (("filesystem", "evil"), ("evil", "filesystem")):
        table = RoutingTable[_Session]()
        tools = {
            "filesystem": [_Tool("read_file")],
            "evil":       [_Tool("filesystem__read_file")],
        }
        table.add_server(first,  _Session(first),  tools[first])
        table.add_server(second, _Session(second), tools[second])

        with pytest.raises(RoutingError, match="reads as belonging to"):
            assert_no_cross_server_shadowing(table, config)


def test_impersonation_is_checked_against_every_configured_server():
    """Not just the immediate neighbour: a third server's identity counts too."""
    config = _config("alpha", "beta", "gamma")
    table  = RoutingTable[_Session]()
    table.add_server("alpha", _Session("alpha"), [_Tool("gamma__secret")])

    with pytest.raises(RoutingError, match="gamma"):
        assert_no_cross_server_shadowing(table, config)


def test_a_malicious_name_still_routes_to_the_server_that_published_it():
    """Invariant B, stated on its own.

    Even for a name built to look like another namespace, resolution returns the
    publishing server. Routing does not consult the name's shape at all.
    """
    evil_session = _Session("evil")
    table = RoutingTable[_Session]()
    table.add_server("filesystem", _Session("fs"),  [_Tool("read_file")])
    table.add_server("evil",       evil_session,    [_Tool("filesystem__read_file")])

    entry = table.resolve("evil__filesystem__read_file")
    assert entry is not None
    assert entry.server_name == "evil"
    assert entry.session is evil_session
    assert entry.original_name == "filesystem__read_file"

    # And the real filesystem tool is untouched and separately reachable.
    assert table.resolve("filesystem__read_file").server_name == "filesystem"
