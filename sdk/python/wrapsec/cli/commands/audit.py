"""
wrapsec audit — read-only audit log commands.

All commands are strictly read-only.
No mutation or control-plane logic.

Spec reference: Section 13.2 (wrapsec audit list/get/stats),
                Section 3 (audit must remain read-only)
"""

from __future__ import annotations

import sys

import click

from wrapsec.client import Client
from wrapsec.config.loader import load_config
from wrapsec.exceptions import WrapSecError
from wrapsec.cli._output import print_error, print_json


def _get_client() -> Client:
    cfg = load_config()
    if not cfg.api_key:
        print_error(
            "No API key configured.\n"
            "Run: wrapsec config set api_key wsk_live_..."
        )
        sys.exit(1)
    return Client(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)


@click.group()
def audit() -> None:
    """Query audit logs. All commands are read-only.

    Scope is bounded by the API key used —
    admin key sees all requests, standard key sees only its own.
    """


@audit.command("list")
@click.option("--decision",  default=None, type=click.Choice(["BLOCK", "SANITIZE", "ALLOW"]))
@click.option("--reason",    default=None, help="Filter by primary_reason.")
@click.option("--from",      "from_date",  default=None, help="From date (YYYY-MM-DD).")
@click.option("--to",        "to_date",    default=None, help="To date (YYYY-MM-DD).")
@click.option("--limit",     default=20,   show_default=True, type=click.IntRange(1, 100),
              help="Number of records (max 100).")
@click.option("--json",      "json_output", is_flag=True, help="Pure JSON output.")
def audit_list(
    decision:    str | None,
    reason:      str | None,
    from_date:   str | None,
    to_date:     str | None,
    limit:       int,
    json_output: bool,
) -> None:
    """List recent audit log entries.

    \b
    Examples:
      wrapsec audit list
      wrapsec audit list --decision BLOCK --limit 50
      wrapsec audit list --reason SYSTEM_ERROR
      wrapsec audit list --from 2026-04-01 --to 2026-04-16
      wrapsec audit list --json | jq .[].trace_id
    """
    client = _get_client()
    try:
        logs = client.audit_list(
            decision  = decision,
            reason    = reason,
            from_date = from_date,
            to_date   = to_date,
            limit     = limit,
        )
    except WrapSecError as e:
        print_error(str(e))
        sys.exit(1)

    if json_output:
        print_json([{
            "trace_id":       log.trace_id,
            "decision":       log.decision,
            "primary_reason": log.primary_reason,
            "confidence":     log.confidence,
            "confidence_band":log.confidence_band,
            "threats":        log.threats,
            "latency_ms":     log.latency_ms,
            "key_id":         log.key_id,
            "dept_id":        log.dept_id,
            "app_id":         log.app_id,
            "user_id":        log.user_id,
            "source":         log.source,
            "created_at":     log.created_at,
        } for log in logs])
        return

    if not logs:
        click.echo("No audit records found.")
        return

    # Human-readable table
    click.echo(
        f"{'TRACE ID':<32}  {'DECISION':<10}  {'REASON':<30}  "
        f"{'CONF':<5}  {'BAND':<6}  {'SOURCE':<18}  CREATED"
    )
    click.echo("-" * 120)
    for log in logs:
        color   = {"BLOCK": "red", "SANITIZE": "yellow", "ALLOW": "green"}.get(log.decision)
        reason  = (log.primary_reason or "—")[:30]
        source  = (log.source or "—")[:18]
        created = log.created_at[:19] if log.created_at else "—"
        click.secho(
            f"{log.trace_id:<32}  "
            f"{log.decision:<10}  "
            f"{reason:<30}  "
            f"{round(log.confidence, 2):<5.2f}  "
            f"{log.confidence_band or '—':<5}  "
            f"{source:<18}  "
            f"{created}",
            fg=color,
        )


@audit.command("get")
@click.argument("trace_id")
@click.option("--json", "json_output", is_flag=True, help="Pure JSON output.")
def audit_get(trace_id: str, json_output: bool) -> None:
    """Retrieve full detail of a single audit record by trace ID.

    \b
    Example:
      wrapsec audit get req_01knzhh8
      wrapsec audit get req_01knzhh8 --json
    """
    client = _get_client()
    try:
        log = client.audit_get(trace_id)
    except WrapSecError as e:
        print_error(str(e))
        sys.exit(1)

    if json_output:
        print_json({
            "trace_id":        log.trace_id,
            "decision":        log.decision,
            "primary_reason":  log.primary_reason,
            "confidence":      log.confidence,
            "confidence_band": log.confidence_band,
            "threats":         log.threats,
            "latency_ms":      log.latency_ms,
            "input_length":    log.input_length,
            "key_id":          log.key_id,
            "dept_id":         log.dept_id,
            "app_id":          log.app_id,
            "user_id":         log.user_id,
            "source":          log.source,
            "created_at":      log.created_at,
        })
        return

    color = {"BLOCK": "red", "SANITIZE": "yellow", "ALLOW": "green"}.get(log.decision)
    click.secho(f"Decision:       {log.decision}", fg=color, bold=True)
    click.echo(f"Reason:         {log.primary_reason}")
    click.echo(f"Confidence:     {round(log.confidence, 2)} ({log.confidence_band})")
    click.echo(f"Trace ID:       {log.trace_id}")
    click.echo(f"Latency:        {log.latency_ms:.1f}ms")
    click.echo(f"Input length:   {log.input_length} chars")
    click.echo(f"Created:        {log.created_at}")
    if log.threats:
        click.echo(f"Threats:        {', '.join(log.threats)}")
    if log.key_id:
        click.echo(f"Key ID:         {log.key_id}")
    if log.dept_id:
        click.echo(f"Department:     {log.dept_id}")
    if log.app_id:
        click.echo(f"Application:    {log.app_id}")
    if log.user_id:
        click.echo(f"User:           {log.user_id}")
    if log.source:
        click.echo(f"Source:         {log.source}")


@audit.command("stats")
@click.option("--from", "from_date", default=None, help="From date (YYYY-MM-DD).")
@click.option("--to",   "to_date",   default=None, help="To date (YYYY-MM-DD).")
@click.option("--json", "json_output", is_flag=True, help="Pure JSON output.")
def audit_stats(from_date: str | None, to_date: str | None, json_output: bool) -> None:
    """Show aggregated decision statistics.

    \b
    Examples:
      wrapsec audit stats
      wrapsec audit stats --from 2026-04-01
      wrapsec audit stats --json | jq .block_rate
    """
    client = _get_client()
    try:
        stats = client.audit_stats(from_date=from_date, to_date=to_date)
    except WrapSecError as e:
        print_error(str(e))
        sys.exit(1)

    if json_output:
        print_json({
            "total_requests":  stats.total_requests,
            "block_count":     stats.block_count,
            "sanitize_count":  stats.sanitize_count,
            "allow_count":     stats.allow_count,
            "block_rate":      stats.block_rate,
            "avg_latency_ms":  stats.avg_latency_ms,
            "p95_latency_ms":  stats.p95_latency_ms,
            "top_threats":     stats.top_threats,
            "severity_counts": stats.severity_counts,
        })
        return

    click.echo(f"Total requests:  {stats.total_requests:,}")
    click.secho(f"Blocked:         {stats.block_count:,} ({round(stats.block_rate * 100, 1)}%)",
                fg="red" if stats.block_count else None)
    click.secho(f"Sanitized:       {stats.sanitize_count:,}", fg="yellow" if stats.sanitize_count else None)
    click.secho(f"Allowed:         {stats.allow_count:,}",    fg="green"  if stats.allow_count    else None)
    click.echo(f"Avg latency:     {stats.avg_latency_ms:.1f}ms")
    click.echo(f"P95 latency:     {stats.p95_latency_ms:.1f}ms")
    sev = stats.severity_counts
    if any(sev.values()):
        click.echo("Severity:")
        click.secho(f"  {'CRITICAL':<12} {sev.get('CRITICAL', 0):>6}", fg="red"    if sev.get("CRITICAL") else None)
        click.secho(f"  {'HIGH':<12} {sev.get('HIGH', 0):>6}",     fg="yellow" if sev.get("HIGH")     else None)
        click.secho(f"  {'MEDIUM':<12} {sev.get('MEDIUM', 0):>6}", fg="cyan"   if sev.get("MEDIUM")   else None)
        click.echo( f"  {'LOW':<12} {sev.get('LOW', 0):>6}")
    if stats.top_threats:
        click.echo("Top threats:")
        for t in stats.top_threats:
            click.echo(f"  {t.get('category', '?'):<35} {t.get('count', 0):>6}")
