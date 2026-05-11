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
    cfg      = load_config()
    all_ok   = True

    click.echo("WrapSec Doctor")
    click.echo("=" * 50)

    # ── Check 1: Config file ────────────────────────────────────────────────
    click.echo("\n1. Configuration")
    config_path = get_config_path()
    click.echo(f"   Config file:  {config_path}")

    if cfg.api_key:
        source = get_config_source("api_key")
        click.secho(f"   API key:      {mask_api_key(cfg.api_key)} [{source}]", fg="green")
    else:
        click.secho("   API key:       not set", fg="red")
        click.echo("   Run: wrapsec config set api_key wsk_live_...")
        all_ok = False

    url_source = get_config_source("base_url")
    click.echo(f"   Base URL:     {cfg.base_url} [{url_source}]")

    timeout_source = get_config_source("timeout")
    click.echo(f"   Timeout:      {cfg.timeout}s [{timeout_source}]")

    # ── Check 2: API reachable ──────────────────────────────────────────────
    click.echo("\n2. API Connectivity")
    client = Client(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)

    reachable = client.health_live()
    if reachable:
        click.secho("    API reachable (/health/live)", fg="green")
    else:
        click.secho("    Cannot reach API", fg="red")
        click.echo(f"     Tried: {cfg.base_url}/health/live")
        click.echo("     Check network connection and WRAPSEC_BASE_URL.")
        all_ok = False

    # ── Checks 3-5 require API to be reachable ──────────────────────────────
    if not reachable or not cfg.api_key:
        _print_final(all_ok)
        return

    # ── Check 3: Auth valid ─────────────────────────────────────────────────
    click.echo("\n3. Authentication")
    health_data: dict = {}
    try:
        health_data = client.health_ready()
        click.secho("    API key valid (/health/ready)", fg="green")
    except WrapSecError as e:
        click.secho(f"    Auth failed: {e.message}", fg="red")
        all_ok = False

    # ── Check 4: Service health ─────────────────────────────────────────────
    click.echo("\n4. Service Health")
    checks = {}
    try:
        checks = health_data.get("checks", {})
    except Exception:
        pass

    if not checks:
        click.echo("   - No health check data available")
    else:
        for svc, status in checks.items():
            # Resilient: handle unexpected types/missing fields
            # Spec: Section 13.2 - missing fields show "Unknown"
            status_str = str(status) if status is not None else "Unknown"
            ok = status_str.lower() == "ok"
            icon  = "[ok]" if ok else "[!!]"
            color = "green" if ok else "red"
            click.secho(f"   {icon} {svc:<15} {status_str}", fg=color)
            if not ok:
                all_ok = False

    # ── Checks 5+6: fetch config once, reuse for both ──────────────────────
    config_data: dict = {}
    try:
        config_data = client.health_config()
    except Exception:
        pass

    # ── Check 5: Configuration summary ─────────────────────────────────────
    click.echo("\n5. Active Configuration")
    if config_data:
        thresholds = config_data.get("thresholds", {})
        layers     = config_data.get("detection_layers", {})
        click.echo(f"   Block threshold:   {thresholds.get('block', 'Unknown')}")
        click.echo(f"   Sanitize threshold:{thresholds.get('sanitize', 'Unknown')}")
        click.echo(f"   Rule detector:     {'enabled' if layers.get('rule') else 'disabled'}")
        click.echo(f"   ML detector:       {'enabled' if layers.get('ml') else 'disabled'}")
        click.echo(f"   LLM detector:      {'enabled' if layers.get('llm') else 'disabled'}")
    else:
        click.echo("   - Configuration data unavailable")

    # ── Check 6: Version compatibility ─────────────────────────────────────
    click.echo("\n6. Version Compatibility")
    click.echo(f"   CLI version:   {__version__}")
    click.echo(f"   Expected API:  {EXPECTED_API_VERSION}")

    api_version = config_data.get("version", "Unknown") if config_data else "Unknown"

    click.echo(f"   API version:   {api_version}")

    # API version from /health/config is a semantic version (e.g. "1.0.0")
    # CLI expected API is a path version ("v1") - major version 1.x.x = v1 compatible
    # Spec: Section 6.6 - version mismatch warning only, never blocks
    compatible = (
        api_version == "Unknown"
        or api_version.startswith("1.")   # 1.x.x = API v1 compatible
    )
    if not compatible:
        click.secho(
            f"   [!!] Version mismatch: CLI expects API v1 (1.x.x), "
            f"API reports {api_version}.\n"
            f"     Some features may not work correctly.",
            fg="yellow",
            err=True,
        )
    else:
        click.secho(f"    Compatible ({api_version})", fg="green")

    # ── Final summary ───────────────────────────────────────────────────────
    _print_final(all_ok)


def _print_final(all_ok: bool) -> None:
    click.echo("")
    if all_ok:
        click.secho(" All checks passed - WrapSec CLI is ready.", fg="green")
        sys.exit(0)
    else:
        click.secho(" Some checks failed - see above for details.", fg="red", err=True)
        sys.exit(1)
