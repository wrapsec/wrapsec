# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
wrapsec keys list - list API keys. Read-only.

Does NOT show key secrets - they are never retrievable after creation.
Does NOT support create or revoke - use the dashboard for those.

Spec reference: Section 13.2 (wrapsec keys list),
                Section 22 (Non-Goals - no key creation or revocation via CLI)
"""

from __future__ import annotations

import sys

import click

from wrapsec.client import Client
from wrapsec.config.loader import load_config
from wrapsec.exceptions import WrapSecError
from wrapsec.cli._output import print_error, print_json


@click.group()
def keys() -> None:
    """List API keys. Read-only.

    To create or revoke keys, use the dashboard.
    """


@keys.command("list")
@click.option("--json", "json_output", is_flag=True, help="Pure JSON output.")
def keys_list(json_output: bool) -> None:
    """List API keys visible to the current key.

    \b
    Shows: key_id, name, created_at, last_used_at
    Does NOT show: key secrets (never retrievable after creation)

    \b
    To create or revoke keys, use the dashboard.
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
        key_list = client.keys_list()
    except WrapSecError as e:
        print_error(str(e))
        sys.exit(1)

    if json_output:
        # Never include key secret in JSON output - it's not in the response anyway
        print_json(key_list)
        return

    if not key_list:
        click.echo("No API keys found.")
        return

    click.echo(f"{'KEY ID':<25}  {'NAME':<30}  {'CREATED':<12}  LAST USED")
    click.echo("-" * 85)
    for k in key_list:
        last_used = k.get("last_used_at", "")
        last_used = last_used[:10] if last_used else "Never"
        created   = (k.get("created_at") or "")[:10]
        click.echo(
            f"{k.get('key_id', ''):<25}  "
            f"{k.get('name', ''):<30}  "
            f"{created:<12}  "
            f"{last_used}"
        )
