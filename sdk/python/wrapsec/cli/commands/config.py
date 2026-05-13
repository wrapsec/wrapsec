# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
wrapsec config - manage CLI configuration (api_key, base_url, timeout).

This command manages the CLI's OWN configuration file.
It does NOT touch gateway settings - use `wrapsec settings get` for that.

Spec reference: Section 13.2 (wrapsec config), Section 10.4 (security rules)
"""

from __future__ import annotations

import sys

import click

from wrapsec.config.loader import (
    clear_config,
    get_config_path,
    get_config_source,
    load_config,
    mask_api_key,
    set_config_value,
)
from wrapsec.config.schema import ALLOWED_CONFIG_KEYS, validate_config_value
from wrapsec.cli._output import print_error, print_success


@click.group()
def config() -> None:
    """Manage CLI configuration (api_key, base_url, timeout).

    \b
    Allowed keys:
      api_key   Your WrapSec API key (must start with wsk_live_)
      base_url  WrapSec API base URL (default: http://localhost:8000)
      timeout   Request timeout in seconds, min 1 (default: 30)

    \b
    Config file location:
      Linux/macOS: $XDG_CONFIG_HOME/wrapsec/config.json
      Windows:     %APPDATA%\\wrapsec\\config.json

    \b
    Environment variables (override config file):
      WRAPSEC_API_KEY, WRAPSEC_BASE_URL, WRAPSEC_TIMEOUT
    """


@config.command("set")
@click.argument("key", type=click.Choice(list(ALLOWED_CONFIG_KEYS), case_sensitive=False))
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set a configuration value.

    Validates the value before writing.
    For api_key, the stored value is never shown in plain text.

    \b
    Examples:
      wrapsec config set api_key wsk_live_abc123
      wrapsec config set base_url http://localhost:8000
      wrapsec config set timeout 60
    """
    try:
        set_config_value(key, value)
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)

    if key == "api_key":
        display = mask_api_key(value)
    else:
        display = value

    print_success(f"{key} saved ({display})")


@config.command("get")
def config_get() -> None:
    """Show current configuration.

    API key is always masked. Shows the source of each value
    (environment variable, config file, or default).
    """
    cfg  = load_config()
    path = get_config_path()

    click.echo(f"Config file: {path}")
    click.echo("")

    rows = [
        ("api_key",  mask_api_key(cfg.api_key), get_config_source("api_key")),
        ("base_url", cfg.base_url,              get_config_source("base_url")),
        ("timeout",  str(cfg.timeout),          get_config_source("timeout")),
    ]

    for key, value, source in rows:
        click.echo(f"  {key:<10}  {value:<40}  [{source}]")

    if not cfg.api_key:
        click.echo("")
        click.echo("No API key set. Run:")
        click.echo("  wrapsec config set api_key wsk_live_...")


@config.command("clear")
@click.option("--force", is_flag=True, help="Skip confirmation prompt (for CI environments).")
def config_clear(force: bool) -> None:
    """Remove all stored configuration.

    \b
    Interactive (default):
      Prompts for confirmation before clearing.
      Default answer is N (safe - Enter alone does not clear).

    \b
    Non-interactive (CI):
      wrapsec config clear --force
      Skips confirmation. For use in CI teardown scripts.

    Spec: Section 13.2 - --force skips confirmation for CI
    """
    if not force:
        confirmed = click.confirm(
            "Remove your API key and all stored settings?",
            default=False,
        )
        if not confirmed:
            click.echo("Cancelled.")
            return

    clear_config()
    print_success("Configuration cleared.")
