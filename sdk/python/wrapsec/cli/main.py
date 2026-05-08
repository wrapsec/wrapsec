# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec CLI — root click group.
All subcommands registered here.

Spec reference: Section 2.1 (cli/main.py), Section 13.1 (command set)
"""

from __future__ import annotations

import signal
import sys

import click

from wrapsec import __version__


# ── SIGPIPE guard — Unix only ───────────────────────────────────────────────
# Spec: Section 14.3
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


# ── Windows stdin UTF-8 ─────────────────────────────────────────────────────
# Spec: Section 14.2
if sys.platform == "win32" and hasattr(sys.stdin, "reconfigure"):
    try:
        sys.stdin.reconfigure(encoding="utf-8")
    except Exception:
        pass


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="wrapsec")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """WrapSec CLI — AI Security Gateway

    Scan and validate LLM inputs before sending to models.

    \b
    Exit codes:
      0   ALLOW or SANITIZE (input accepted)
      1   CLI error, network failure, auth error, rate limit, SYSTEM_ERROR
      2   BLOCK (input rejected by security policy)

    \b
    Security note:
      Avoid passing sensitive content as CLI arguments — they are stored
      in shell history. Use stdin instead:
        echo "sensitive text" | wrapsec scan

    \b
    Quick start:
      wrapsec config set api_key wwsk_live_...
      wrapsec scan "hello world"
      wrapsec doctor
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ── Register all subcommands ────────────────────────────────────────────────

from wrapsec.cli.commands.scan     import scan      # noqa: E402
from wrapsec.cli.commands.batch    import batch     # noqa: E402
from wrapsec.cli.commands.audit    import audit     # noqa: E402
from wrapsec.cli.commands.settings import settings  # noqa: E402
from wrapsec.cli.commands.keys     import keys      # noqa: E402
from wrapsec.cli.commands.config   import config    # noqa: E402
from wrapsec.cli.commands.doctor   import ping, doctor  # noqa: E402

cli.add_command(scan)
cli.add_command(batch)
cli.add_command(audit)
cli.add_command(settings)
cli.add_command(keys)
cli.add_command(config)
cli.add_command(ping)
cli.add_command(doctor)
