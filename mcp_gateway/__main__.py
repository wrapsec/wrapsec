# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Entry point: `python -m mcp_gateway` serves one agent over stdio.

STARTUP ORDER IS A SECURITY PROPERTY, not a convenience:

  1. verify the MCP package         -- refuse an SDK whose APIs moved
  2. load and validate config       -- refuse ambiguous routing or policy
  3. require enforcement            -- refuse pass-through outside development
  4. connect downstream servers     -- refuse a partial tool set
  5. only then serve

Every step before (5) can refuse. Nothing is served by a process that could not
complete all four, because a gateway that starts in a degraded state looks
identical from the outside to one that is working.
"""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)

EXIT_STARTUP_REFUSED = 2


async def _run() -> int:
    from mcp_gateway.mcp_compat import UnsupportedMCPPackage, verify_mcp_package
    from mcp_gateway.proxy import EnforcementDisabled, Gateway
    from mcp_gateway.session import DownstreamPool
    from mcp_gateway.transports import stdio

    stdio.configure_logging()

    try:
        verify_mcp_package()
    except UnsupportedMCPPackage as exc:
        logger.error("%s", exc)
        return EXIT_STARTUP_REFUSED

    try:
        config = _load_config()
    except Exception as exc:
        logger.error("configuration refused: %s", exc)
        return EXIT_STARTUP_REFUSED

    pool    = DownstreamPool()
    gateway = Gateway(config, pool)

    try:
        gateway.require_enforcement(
            environment=os.environ.get("WRAPSEC_ENV", "production")
        )
    except EnforcementDisabled as exc:
        logger.error("%s", exc)
        return EXIT_STARTUP_REFUSED

    try:
        await gateway.connect_all()
    except Exception as exc:
        logger.error("downstream startup refused: %s", exc)
        await pool.aclose()
        return EXIT_STARTUP_REFUSED

    logger.info(
        "serving %d tool(s) from %d downstream server(s)",
        len(gateway.routes), len(config.servers),
    )

    try:
        await stdio.serve(gateway.build_server())
    finally:
        await pool.aclose()
    return 0


CONFIG_ENV = "WRAPSEC_MCP_CONFIG"


def _load_config():
    """Read the gateway configuration named by the environment.

    There is no default path and no default configuration. A gateway that
    guessed which servers to connect to, or what to permit, would be inventing
    the operator's intent; an unset variable is a startup refusal.
    """
    import os

    from mcp_gateway.config import ConfigError, load_config

    path = os.environ.get(CONFIG_ENV)
    if not path:
        raise ConfigError(
            f"{CONFIG_ENV} is not set; the gateway has no configuration to load "
            f"and will not guess one"
        )
    return load_config(path)


def main() -> int:
    import anyio

    return anyio.run(_run)


if __name__ == "__main__":
    sys.exit(main())
