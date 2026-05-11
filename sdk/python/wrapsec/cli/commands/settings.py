# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
wrapsec settings get - show active gateway configuration.

Read-only. No write operations.
Distinct from `wrapsec config` which manages the CLI's own config file.

Spec reference: Section 13.2 (wrapsec settings get),
                Section 22 (Non-Goals - no write operations via CLI)
"""

from __future__ import annotations

import sys

import click

from wrapsec.client import Client
from wrapsec.config.loader import load_config
from wrapsec.exceptions import WrapSecError
from wrapsec.cli._output import print_error, print_json


@click.group()
def settings() -> None:
    """Show active gateway configuration. Read-only.

    To change any settings, use the dashboard.
    """


@settings.command("get")
@click.option("--json", "json_output", is_flag=True, help="Pure JSON output.")
def settings_get(json_output: bool) -> None:
    """Show active gateway configuration.

    \b
    Shows:
      Block and sanitize thresholds (and config source)
      Detection layers: rule, ML, LLM (enabled/disabled)
      LLM provider, model, timeout, trigger threshold
      Rate limit per minute

    \b
    To change any settings, use the dashboard.

    \b
    Note: 'settings' shows the live gateway configuration.
          For CLI config (api_key, base_url), use 'wrapsec config get'.
    """
    cfg = load_config()
    if not cfg.api_key:
        print_error(
            "No API key configured.\n"
            "Run: wrapsec config set api_key wsk_live_..."
        )
        sys.exit(1)

    client = Client(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)

    try:
        data = client.settings_get()
    except WrapSecError as e:
        print_error(str(e))
        sys.exit(1)

    if json_output:
        print_json(data)
        return

    thresholds  = data.get("thresholds", {})
    layers      = data.get("layers", {})
    llm         = data.get("llm", {})
    rate_limit  = data.get("rate_limit", {})

    click.echo("Gateway Configuration (read-only - change via dashboard)")

    # Thresholds
    click.echo("\nDetection Thresholds:")
    click.echo(f"  Block threshold:     {thresholds.get('block_threshold', '-')}")
    click.echo(f"  Sanitize threshold:  {thresholds.get('sanitize_threshold', '-')}")

    # Detection layers
    click.echo("\nDetection Layers:")
    for layer in ("rule_enabled", "ml_enabled", "llm_enabled"):
        enabled = layers.get(layer)
        name    = layer.replace("_enabled", "").upper()
        if enabled is True:
            click.secho(f"  {name:<6}   enabled", fg="green")
        elif enabled is False:
            click.secho(f"  {name:<6}   disabled", fg="yellow")
        else:
            click.echo(f"  {name:<6}  - unknown")

    # LLM
    click.echo("\nLLM Configuration:")
    click.echo(f"  Provider:    {llm.get('provider', '-')}")
    click.echo(f"  Model:       {llm.get('model', '-')}")
    click.echo(f"  Timeout:     {llm.get('timeout', '-')}s")
    click.echo(f"  LLM trigger: {llm.get('llm_trigger', '-')}")

    # Rate limit
    click.echo("\nRate Limit:")
    click.echo(f"  Live keys:   {rate_limit.get('per_minute', '-')} req/min ({rate_limit.get('source', '-')})")
