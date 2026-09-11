# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Startup order is a security property, so it is tested as one.

Four things can refuse before anything is served: an SDK whose APIs moved, an
unusable configuration, a gateway with no enforcement outside development, and a
downstream server that will not start. Each must stop the process rather than
degrade it, because a gateway serving in a degraded state is indistinguishable
from a working one.

The end-to-end test proves the real process refuses; these prove each refusal
individually, and that one cannot be reached past another.
"""

from __future__ import annotations

import logging
import sys

import pytest

from mcp_gateway import __main__ as entry
from mcp_gateway.config import ConfigError
from mcp_gateway.transports import stdio

# ---------------------------------------------------------------------------
# configuration source
# ---------------------------------------------------------------------------

def test_an_unset_config_variable_refuses(monkeypatch):
    """No default path. A gateway that guessed would choose what to trust."""
    monkeypatch.delenv(entry.CONFIG_ENV, raising=False)

    with pytest.raises(ConfigError, match=entry.CONFIG_ENV):
        entry._load_config()


def test_an_empty_config_variable_refuses(monkeypatch):
    """An empty value is as unusable as an absent one and must not read ''."""
    monkeypatch.setenv(entry.CONFIG_ENV, "")

    with pytest.raises(ConfigError, match=entry.CONFIG_ENV):
        entry._load_config()


def test_the_named_file_is_what_gets_loaded(monkeypatch, tmp_path):
    config = tmp_path / "g.yaml"
    config.write_text("servers:\n  - name: only\n    command: [a]\n", encoding="utf-8")
    monkeypatch.setenv(entry.CONFIG_ENV, str(config))

    loaded = entry._load_config()
    assert [s.name for s in loaded.servers] == ["only"]


# ---------------------------------------------------------------------------
# refusal ordering
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_an_unsupported_sdk_refuses_before_anything_else(monkeypatch):
    """The SDK check runs first: a changed enforcement API must stop the process
    before a configuration is even read."""
    from mcp_gateway.mcp_compat import UnsupportedMCPPackage

    def _boom() -> None:
        raise UnsupportedMCPPackage("an API moved")

    monkeypatch.setattr("mcp_gateway.mcp_compat.verify_mcp_package", _boom)
    read: list[str] = []
    monkeypatch.setattr(entry, "_load_config", lambda: read.append("read"))

    assert await entry._run() == entry.EXIT_STARTUP_REFUSED
    assert read == [], "configuration was read despite an unusable SDK"


@pytest.mark.asyncio
async def test_an_unusable_configuration_refuses(monkeypatch):
    monkeypatch.setattr("mcp_gateway.mcp_compat.verify_mcp_package", lambda: None)
    monkeypatch.setattr(entry, "_load_config", _raise(ConfigError("bad config")))

    assert await entry._run() == entry.EXIT_STARTUP_REFUSED


@pytest.mark.asyncio
async def test_a_downstream_that_will_not_start_refuses(monkeypatch, tmp_path):
    """A partial tool set is not served: an agent would silently lose capability
    and the operator would see only a missing tool."""
    from mcp_gateway.config import GatewayConfig, ServerConfig
    from mcp_gateway.session import DownstreamUnavailable

    monkeypatch.setattr("mcp_gateway.mcp_compat.verify_mcp_package", lambda: None)
    monkeypatch.setattr(entry, "_load_config", lambda: GatewayConfig(
        servers=(ServerConfig(name="only", command=("does-not-exist",)),)
    ))
    monkeypatch.setenv("WRAPSEC_ENV", "development")

    async def _fail(self, config):
        raise DownstreamUnavailable("cannot spawn")

    monkeypatch.setattr("mcp_gateway.session.DownstreamPool.connect", _fail)

    assert await entry._run() == entry.EXIT_STARTUP_REFUSED


@pytest.mark.asyncio
async def test_pass_through_refuses_before_connecting_downstream(monkeypatch):
    """Enforcement is checked BEFORE downstream servers are spawned, so a
    misconfigured gateway never starts subprocesses it will not use."""
    from mcp_gateway.config import GatewayConfig, ServerConfig

    monkeypatch.setattr("mcp_gateway.mcp_compat.verify_mcp_package", lambda: None)
    monkeypatch.setattr(entry, "_load_config", lambda: GatewayConfig(
        servers=(ServerConfig(name="only", command=("a",)),)
    ))
    monkeypatch.setenv("WRAPSEC_ENV", "production")

    connected: list[str] = []

    async def _record(self, config):
        connected.append(config.name)

    monkeypatch.setattr("mcp_gateway.session.DownstreamPool.connect", _record)

    assert await entry._run() == entry.EXIT_STARTUP_REFUSED
    assert connected == [], "downstream servers were spawned despite the refusal"


def test_the_refusal_exit_code_is_not_success():
    """A supervisor distinguishes a refusal from a clean shutdown by this."""
    assert entry.EXIT_STARTUP_REFUSED != 0


# ---------------------------------------------------------------------------
# stdout belongs to the protocol
# ---------------------------------------------------------------------------

def test_logging_is_configured_onto_stderr():
    """A handler on stdout would interleave log lines with protocol frames and
    take the connection down, which in a security component would look like a
    fault in whatever was being inspected."""
    stdio.configure_logging()

    handlers = logging.getLogger().handlers
    assert handlers, "no handler was installed"
    for handler in handlers:
        assert getattr(handler, "stream", None) is not sys.stdout, (
            "a log handler writes to stdout, which carries the MCP protocol"
        )
    assert any(getattr(h, "stream", None) is sys.stderr for h in handlers)


@pytest.mark.asyncio
async def test_serve_runs_the_server_over_the_stdio_streams(monkeypatch):
    """The transport hands the server the streams and its initialization options
    rather than inventing a connection of its own."""
    import contextlib

    ran: dict = {}

    @contextlib.asynccontextmanager
    async def _fake_stdio_server():
        yield ("READ", "WRITE")

    class _Server:
        def create_initialization_options(self):
            return "OPTS"

        async def run(self, read, write, options):
            ran.update(read=read, write=write, options=options)

    monkeypatch.setattr("mcp.server.stdio.stdio_server", _fake_stdio_server)
    await stdio.serve(_Server())

    assert ran == {"read": "READ", "write": "WRITE", "options": "OPTS"}


def _raise(exc: BaseException):
    def _fn(*args, **kwargs):
        raise exc
    return _fn
