# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""The whole chain, as a real agent would use it.

    MCP client  ->stdio->  python -m mcp_gateway  ->stdio->  downstream servers

Every part is real: a genuine MCP client, the gateway started as its own process
through its own entry point, and two downstream MCP servers the gateway spawns
itself from a configuration file. Nothing here is a stand-in, which is the point.
The handler-level tests prove the logic; this proves the process works.

TWO downstream servers, deliberately. Routing identity is only observable when
more than one server could have answered: each fake server reports its own name,
so a result names which one actually ran.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_ROOT  = Path(__file__).resolve().parents[3]
_PY    = str(_ROOT / ".venv" / "bin" / "python")
_FAKE  = str(Path(__file__).parent / "_fake_downstream.py")

pytestmark = pytest.mark.skipif(
    not Path(_PY).exists(),
    reason="the project interpreter is required to spawn the gateway",
)


def _config_file(tmp_path: Path) -> Path:
    """Two downstream servers, each an instance of the same fake with its own
    identity, so a routed call can be attributed."""
    path = tmp_path / "gateway.yaml"
    path.write_text(
        "servers:\n"
        "  - name: alpha\n"
        "    transport: stdio\n"
        "    command:\n"
        f"      - {_PY}\n"
        f"      - {_FAKE}\n"
        "      - alpha\n"
        "  - name: beta\n"
        "    transport: stdio\n"
        "    command:\n"
        f"      - {_PY}\n"
        f"      - {_FAKE}\n"
        "      - beta\n",
        encoding="utf-8",
    )
    return path


def _gateway_params(config: Path, **overrides: str):
    """Launch parameters for the gateway's real entry point."""
    from mcp.client.stdio import StdioServerParameters

    env = {
        "PATH":                os.environ.get("PATH", ""),
        "PYTHONPATH":          str(_ROOT),
        "WRAPSEC_MCP_CONFIG":  str(config),
        # Phase 1 ships the pass-through interceptor, which the gateway refuses
        # to run outside development. That refusal is asserted separately.
        "WRAPSEC_ENV":         "development",
    }
    env.update(overrides)
    return StdioServerParameters(command=_PY, args=["-m", "mcp_gateway"], env=env)


@pytest.mark.asyncio
async def test_the_full_chain_serves_normal_mcp_traffic(tmp_path):
    """Lifecycle, tools/list, and a routed call, through the real processes."""
    from mcp.client.session import ClientSession
    from mcp.client.stdio import stdio_client

    params = _gateway_params(_config_file(tmp_path))

    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        # 1. the normal MCP lifecycle completes through the gateway
        info = await session.initialize()
        assert info.server_info.name == "wrapsec-mcp-gateway"

        # 2. tools/list returns both servers' tools, namespaced
        listed = sorted(t.name for t in (await session.list_tools()).tools)
        assert listed == [
            "alpha__echo", "alpha__whoami",
            "beta__echo",  "beta__whoami",
        ], listed

        # 3. a call reaches the server the namespace names, and returns ITS
        #    result -- not the other server's, and not a gateway stand-in
        alpha = await session.call_tool("alpha__whoami", {})
        beta  = await session.call_tool("beta__whoami", {})

        assert "handled by alpha" in _text(alpha)
        assert "handled by beta"  in _text(beta)

        # 4. arguments survive the hop, and the downstream server sees its
        #    OWN tool name rather than the namespaced one
        echoed = await session.call_tool("beta__echo", {"text": "payload"})
        assert "beta:payload" in _text(echoed)


@pytest.mark.asyncio
async def test_an_unresolved_tool_is_refused_through_the_real_chain(tmp_path):
    """The refusal contract, delivered as a valid MCP result rather than a fault."""
    from mcp.client.session import ClientSession
    from mcp.client.stdio import stdio_client

    params = _gateway_params(_config_file(tmp_path))

    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        result = await session.call_tool("alpha__does_not_exist", {})

    assert result.is_error is True
    text = _text(result)
    assert "not available" in text
    assert "Do not retry" in text
    assert "Trace:" in text


@pytest.mark.asyncio
async def test_a_call_cannot_reach_a_server_the_namespace_does_not_name(tmp_path):
    """Structured routing, observed from outside the process.

    `beta__whoami` must never be answered by alpha. With two identical servers
    distinguished only by the name they report, a routing mistake is visible in
    the result rather than hidden behind matching output.
    """
    from mcp.client.session import ClientSession
    from mcp.client.stdio import stdio_client

    params = _gateway_params(_config_file(tmp_path))

    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        result = await session.call_tool("beta__whoami", {})

    assert "handled by beta"  in _text(result)
    assert "handled by alpha" not in _text(result)


def test_the_gateway_refuses_to_start_without_a_configuration(tmp_path):
    """No configuration means no guess: the process must exit rather than serve."""
    import subprocess

    env = {
        "PATH":       os.environ.get("PATH", ""),
        "PYTHONPATH": str(_ROOT),
        "WRAPSEC_ENV": "development",
        # WRAPSEC_MCP_CONFIG deliberately unset
    }
    done = subprocess.run(
        [_PY, "-m", "mcp_gateway"],
        env=env, capture_output=True, text=True, timeout=60,
        stdin=subprocess.DEVNULL, check=False,
    )

    assert done.returncode != 0, "the gateway served without a configuration"
    assert "WRAPSEC_MCP_CONFIG" in done.stderr


def test_the_gateway_refuses_pass_through_outside_development(tmp_path):
    """The protocol-only mode must not be reachable by configuration alone."""
    import subprocess

    config = _config_file(tmp_path)
    env = {
        "PATH":               os.environ.get("PATH", ""),
        "PYTHONPATH":         str(_ROOT),
        "WRAPSEC_MCP_CONFIG": str(config),
        "WRAPSEC_ENV":        "production",
    }
    done = subprocess.run(
        [_PY, "-m", "mcp_gateway"],
        env=env, capture_output=True, text=True, timeout=60,
        stdin=subprocess.DEVNULL, check=False,
    )

    assert done.returncode != 0, "a gateway that inspects nothing served in production"
    assert "development and test" in done.stderr


def _text(result) -> str:
    return "".join(
        block.text for block in (result.content or []) if getattr(block, "text", None)
    )


if __name__ == "__main__":  # pragma: no cover - convenience only
    sys.exit(pytest.main([__file__, "-v"]))


# ---------------------------------------------------------------------------
# scan posture, as the real process applies it
# ---------------------------------------------------------------------------

def _posture_config(tmp_path: Path, scan: str) -> Path:
    """A config with a detection API and an explicit scan posture."""
    path = tmp_path / "posture.yaml"
    path.write_text(
        "servers:\n"
        "  - name: alpha\n"
        "    command:\n"
        f"      - {_PY}\n"
        f"      - {_FAKE}\n"
        "      - alpha\n"
        "wrapsec:\n"
        "  base_url: http://localhost:8000\n"
        "  api_key_env: WRAPSEC_API_KEY\n"
        f"{scan}",
        encoding="utf-8",
    )
    return path


def _run_gateway(config: Path, env_extra: dict[str, str]):
    """Start the gateway as a real process and let it reach EOF on stdin."""
    import subprocess

    env = {
        "PATH":               os.environ.get("PATH", ""),
        "PYTHONPATH":         str(_ROOT),
        "WRAPSEC_MCP_CONFIG": str(config),
        "WRAPSEC_API_KEY":    "wsk_live_testing_only",
    }
    env.update(env_extra)
    return subprocess.run(
        [_PY, "-m", "mcp_gateway"],
        env=env, capture_output=True, text=True, timeout=120,
        stdin=subprocess.DEVNULL, check=False,
    )


def test_production_with_every_scan_switch_off_refuses_before_serving(tmp_path):
    """Holding an enforcing interceptor is not the same as enforcing.

    With every boundary switched off the gateway would inspect nothing while
    presenting itself as enforcing, which is the disabled mode under another
    name and the more dangerous form of it -- it looks like a working gateway.
    """
    config = _posture_config(tmp_path, (
        "scan:\n"
        "  tool_definitions: false\n"
        "  results: false\n"
        "  call_arguments: false\n"
    ))

    done = _run_gateway(config, {"WRAPSEC_ENV": "production"})

    assert done.returncode != 0, "a gateway inspecting nothing served in production"
    assert "inspect nothing" in done.stderr
    assert "serving" not in done.stderr, "it reached the serving stage before refusing"


def test_production_with_a_partial_posture_starts_and_records_it(tmp_path):
    """A partial posture is the operator's call, and must be visible.

    Someone who has vetted their tool definitions out of band may reasonably
    scan only results. What must not happen is that choice being invisible.
    """
    config = _posture_config(tmp_path, (
        "scan:\n"
        "  tool_definitions: false\n"
        "  results: true\n"
        "  call_arguments: false\n"
    ))

    done = _run_gateway(config, {"WRAPSEC_ENV": "production"})

    assert done.returncode == 0, f"the gateway refused a partial posture: {done.stderr[-400:]}"
    assert "scan posture:" in done.stderr
    assert "mode=fast" in done.stderr
    assert "inspecting=tool-results" in done.stderr, (
        f"the recorded posture does not name exactly what is inspected: {done.stderr[-300:]}"
    )
    assert "tool-definitions" not in done.stderr.split("inspecting=")[1].split()[0]


def test_the_default_posture_is_recorded_too(tmp_path):
    """A config that omits the scan section still states what is in force, so
    the posture is read rather than inferred from an omission."""
    config = _posture_config(tmp_path, "")

    done = _run_gateway(config, {"WRAPSEC_ENV": "production"})

    assert done.returncode == 0, done.stderr[-400:]
    assert "inspecting=tool-definitions,tool-results,call-arguments" in done.stderr
