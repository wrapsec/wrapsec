# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
wrapsec ping - network connectivity check (no auth).
wrapsec doctor - full health, auth, and version check.

Doctor is resilient - a failed check never aborts remaining checks.
Missing or unexpected response fields show "Unknown", not a crash.

Spec reference: Section 13.2 (wrapsec ping, wrapsec doctor),
                Section 6.6 (version compatibility in doctor)
"""

from __future__ import annotations

import sys

import click

from wrapsec import __version__
from wrapsec.client import Client
from wrapsec.config.loader import (
    get_config_path,
    get_config_source,
    load_config,
    mask_api_key,
)
from wrapsec.exceptions import WrapSecError

# Expected API version - matches BASE_PATH "/v1"
EXPECTED_API_VERSION = "v1"
COMPATIBLE_API_VERSIONS = {"1.0.0", "1.0.1", "1.1.0"}  # semantic versions from /health/config


@click.command()
def ping() -> None:
    """Check if the WrapSec API is reachable.

    Tests network connectivity only - does NOT validate your API key.
    Use 'wrapsec doctor' for a full auth and health check.

    Fixed timeout: 5 seconds.

    \b
    Exit codes:
      0   API reachable
      1   API unreachable

    \b
    Docker health check usage:
      HEALTHCHECK CMD wrapsec ping || exit 1
    """
    cfg    = load_config()
    client = Client(base_url=cfg.base_url)

    reachable = client.health_live()

    if reachable:
        click.secho(" WrapSec API is reachable", fg="green")
        sys.exit(0)
    else:
        click.secho(
            f" Cannot reach WrapSec API.\n"
            f"   Check your network connection and base_url.\n"
            f"   Run 'wrapsec doctor' for detailed diagnostics.",
            fg="red",
            err=True,
        )
        sys.exit(1)


@click.command()
def doctor() -> None:
    """Full connectivity, authentication, and version check.

    Runs all checks independently - a failed check never aborts
    remaining checks. Missing response fields show 'Unknown'.

    \b
    Checks:
      1. Config file found (API key masked)
      2. API reachable (/health/live)
      3. API key valid (/health/ready)
      4. Service health: database, redis, ml_model
      5. Active configuration summary
      6. Version compatibility
      7. Timeout configuration

    \b
    Version mismatch: warning only - never blocks execution.
    """
    cfg    = load_config()
    all_ok = True

    click.echo("")
    click.secho("wrapsec doctor", bold=True)

    # ── Check 1: Config ─────────────────────────────────────────────────────
    click.echo("")
    click.secho("  Configuration", bold=True)
    config_path = get_config_path()
    click.echo(f"    config file   {config_path}")

    if cfg.api_key:
        source = get_config_source("api_key")
        click.echo(f"    api key       {mask_api_key(cfg.api_key)}  ({source})")
    else:
        click.secho("    api key       not set", fg="red")
        click.echo("                  run: wrapsec config set api_key wsk_live_...")
        all_ok = False

    url_source = get_config_source("base_url")
    click.echo(f"    base url      {cfg.base_url}  ({url_source})")

    timeout_source = get_config_source("timeout")
    click.echo(f"    timeout       {cfg.timeout}s  ({timeout_source})")

    # ── Check 2: Connectivity ───────────────────────────────────────────────
    click.echo("")
    click.secho("  Connectivity", bold=True)
    client = Client(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)

    reachable = client.health_live()
    if reachable:
        click.secho(f"  + reachable    {cfg.base_url}", fg="green")
    else:
        click.secho(f"  - unreachable  {cfg.base_url}", fg="red")
        click.echo("    check your network connection and base_url setting")
        all_ok = False

    if not reachable or not cfg.api_key:
        _print_final(all_ok)
        return

    # ── Check 3: Auth ───────────────────────────────────────────────────────
    click.echo("")
    click.secho("  Authentication", bold=True)
    health_data: dict = {}
    try:
        health_data = client.health_ready()
        click.secho("  + api key valid", fg="green")
    except WrapSecError as e:
        click.secho(f"  - auth failed   {e.message}", fg="red")
        all_ok = False

    # ── Check 4: Services ───────────────────────────────────────────────────
    click.echo("")
    click.secho("  Services", bold=True)
    checks = {}
    try:
        checks = health_data.get("checks", {})
    except Exception:
        pass

    if not checks:
        click.echo("    no service data available")
    else:
        for svc, status in checks.items():
            status_str = str(status) if status is not None else "unknown"
            ok    = status_str.lower() == "ok"
            color = "green" if ok else "red"
            icon  = "+" if ok else "-"
            click.secho(f"  {icon} {svc:<14} {status_str}", fg=color)
            if not ok:
                all_ok = False

    # ── Checks 5+6: fetch config once ──────────────────────────────────────
    config_data: dict = {}
    try:
        config_data = client.health_config()
    except Exception:
        pass

    # ── Check 5: Active config ──────────────────────────────────────────────
    click.echo("")
    click.secho("  Active Configuration", bold=True)
    if config_data:
        thresholds = config_data.get("thresholds", {})
        layers     = config_data.get("detection_layers", {})
        click.echo(f"    block threshold   {thresholds.get('block', 'unknown')}")
        click.echo(f"    sanitize          {thresholds.get('sanitize', 'unknown')}")
        click.echo(f"    rule detector     {'enabled' if layers.get('rule') else 'disabled'}")
        click.echo(f"    ml detector       {'enabled' if layers.get('ml') else 'disabled'}")
        click.echo(f"    llm detector      {'enabled' if layers.get('llm') else 'disabled'}")
    else:
        click.echo("    not available  (requires admin or scan key with config access)")

    # ── Check 6: Version ────────────────────────────────────────────────────
    click.echo("")
    click.secho("  Version", bold=True)
    api_version = config_data.get("version", "unknown") if config_data else "unknown"
    click.echo(f"    cli   {__version__}")
    click.echo(f"    api   {api_version}")

    # 1.x.x = API v1 compatible. unknown = assume compatible.
    compatible = api_version == "unknown" or api_version.startswith("1.")
    if not compatible:
        click.secho(
            f"  ! version mismatch  CLI expects 1.x.x, API reports {api_version}",
            fg="yellow",
            err=True,
        )
    else:
        click.secho(f"  + compatible", fg="green")

    # ── Final summary ───────────────────────────────────────────────────────
    _print_final(all_ok)


def _print_final(all_ok: bool) -> None:
    click.echo("")
    if all_ok:
        click.secho("  all checks passed", fg="green", bold=True)
        sys.exit(0)
    else:
        click.secho("  some checks failed - see above for details", fg="red", bold=True, err=True)
        sys.exit(1)
