# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
wrapsec batch - scan prompts from a file.

Spec reference: Section 13.2 (wrapsec batch), Section 11.3 (Batch Exit Code Priority)

Key rules:
  - File path only - no inline text argument (security rule 2)
  - Streamed line by line - never fully loaded into memory
  - Empty lines and # comments skipped
  - Max file size: 10MB
  - Max line length: 8000 chars (longer lines skipped with warning)
  - Exit priority: ERROR (1) > BLOCK (2) > SUCCESS (0)
  - --json outputs JSONL (newline-delimited JSON, one object per line)
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path

import click

from wrapsec.cli._output import (
    get_scan_exit_code,
    print_error,
    print_warning,
    scan_result_to_dict,
)
from wrapsec.client import Client
from wrapsec.config.loader import load_config
from wrapsec.core.validation import (
    MAX_INPUT_CHARS,
    TURN_INDEX_MAX,
    normalize_text,
    validate_input,
    validate_session_id,
)
from wrapsec.exceptions import WrapSecError, WrapSecRateLimitError

MAX_FILE_BYTES  = 10 * 1024 * 1024   # 10MB
MAX_LINE_CHARS  = MAX_INPUT_CHARS
LARGE_FILE_WARN = 100                 # lines


@click.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option(
    "--mode", "-m",
    default="fast",
    type=click.Choice(["fast", "full"]),
    show_default=True,
    help="Detection mode.",
)
@click.option(
    "--timeout",
    default=None,
    type=int,
    help="Per-request timeout in seconds (min 1, default 30).",
)
@click.option(
    "--delay",
    default=0,
    type=int,
    help="Milliseconds to wait between requests (default 0). "
         "Use --delay 100 for large files to avoid rate limiting.",
)
@click.option(
    "--limit",
    default=None,
    type=click.IntRange(1, None),   # Bug #3 fix: reject 0 and negative values
    help="Maximum number of lines to process. Must be at least 1.",
)
@click.option(
    "--summary",
    is_flag=True,
    help="Show counts only - no individual scores or trace IDs. Recommended for CI.",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="JSONL output (newline-delimited JSON, one object per line). "
         "Compatible with jq, pandas, BigQuery.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="No stdout output. Errors to stderr. Exit code only.",
)
@click.option(
    "--session-id",
    default=None,
    help="Opaque conversation identifier attached to every scan. Max 200 "
         "chars, charset [A-Za-z0-9_.:-]. When set, turn_index auto-increments "
         "from 0 per processed line. Do not put PII here.",
)
@click.option(
    "--run-id",
    default=None,
    help="Opaque identifier for one agent execution, attached to every scan. "
         "Same charset rules as --session-id. Do not put PII here.",
)
def batch(
    file:        str,
    mode:        str,
    timeout:     int | None,
    delay:       int,
    limit:       int | None,
    summary:     bool,
    json_output: bool,
    quiet:       bool,
    session_id:  str | None,
    run_id:      str | None,
) -> None:
    """Scan prompts from FILE (one prompt per line).

    FILE is streamed line by line - never fully loaded into memory.
    Empty lines and lines starting with # are skipped.

    \b
    Limits:
      Max file size:   10MB
      Max line length: 8000 chars (longer lines skipped with warning)

    \b
    Exit code priority: ERROR (1) > BLOCK (2) > SUCCESS (0)
    An error means some prompts were not scanned - results are incomplete.

    \b
    Examples:
      wrapsec batch prompts.txt
      wrapsec batch prompts.txt --delay 100 --summary
      wrapsec batch prompts.txt --json > results.jsonl
      wrapsec batch prompts.txt --quiet   # CI - exit code only
    """
    # Validate timeout at CLI level
    if timeout is not None and timeout < 1:
        print_error(f"timeout must be at least 1 second, got {timeout}")
        sys.exit(1)

    # Fail fast on malformed session/run identifiers.
    try:
        session_id = validate_session_id(session_id, "session_id")
        run_id     = validate_session_id(run_id,     "run_id")
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)

    # Check file size before starting
    # Resolve symlink for size check too - consistent with the open() below
    file_size = os.path.getsize(Path(file).resolve())
    if file_size > MAX_FILE_BYTES:
        mb = file_size / (1024 * 1024)
        print_error(f"File too large ({mb:.1f}MB). Maximum is 10MB.")
        sys.exit(1)

    # Require API key
    cfg = load_config()
    if not cfg.api_key:
        print_error(
            "No API key configured.\n"
            "Run: wrapsec config set api_key wsk_live_..."
        )
        sys.exit(1)

    # Large-file warning - estimate from file size to avoid a second open.
    # Average line length of ~50 chars gives a conservative over-estimate.
    if not quiet and not json_output:
        estimated_lines = file_size // 50
        if estimated_lines > LARGE_FILE_WARN and delay == 0:
            click.echo(
                "Warning: large file - potentially many prompts with no delay.\n"
                "Consider --delay 100 to avoid rate limiting.",
                err=True,
            )
            if not click.confirm("Continue?", default=False):
                click.echo("Cancelled.")
                sys.exit(0)

    client = Client(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)

    # Batch state
    had_error  = False
    had_block  = False
    processed  = 0
    skipped    = 0
    blocked    = 0
    sanitized  = 0
    allowed    = 0
    errors     = 0

    # SIGINT handler
    interrupted = False

    def _sigint(sig: int, frame: object) -> None:
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGINT, _sigint)

    # Fix #8 - resolve symlinks before opening.
    # click.Path(exists=True) confirms the path exists but does not resolve
    # symlinks. A symlink could silently point to a file outside the intended
    # directory (e.g. /etc/passwd, ~/.ssh/id_rsa). resolve() follows all
    # symlinks to the real absolute path, making traversal visible and
    # ensuring we log the actual file being read.
    resolved_path = Path(file).resolve()
    with open(resolved_path, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            if interrupted:
                print_warning("Interrupted by user.", )
                had_error = True
                break

            if limit is not None and processed >= limit:
                break

            line = raw_line.lstrip("\ufeff").strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Skip lines that are too long
            if len(line) > MAX_LINE_CHARS:
                click.secho(
                    f"Line {processed + skipped + 1} skipped: "
                    f"{len(line):,} chars exceeds {MAX_LINE_CHARS:,} char limit.",
                    fg="yellow",
                    err=True,
                )
                skipped += 1
                continue

            # Apply delay between requests
            if delay > 0 and processed > 0:
                time.sleep(delay / 1000)

            # Normalise and validate
            try:
                text = normalize_text(line)
                text = validate_input(text)
            except ValueError as e:
                click.secho(f"Line {processed + 1} skipped: {e}", fg="yellow", err=True)
                skipped += 1
                continue

            # Scan
            try:
                # turn_index auto-increments from 0 per processed line when a
                # session_id is set; NULL otherwise (server treats as absent).
                # Ceiling matches the server validator to fail before the
                # network call on very large files.
                if session_id is not None and processed <= TURN_INDEX_MAX:
                    turn = processed
                else:
                    turn = None

                result = client.scan(
                    text,
                    mode       = mode,
                    user       = "cli-batch",
                    timeout    = timeout,
                    session_id = session_id,
                    turn_index = turn,
                    run_id     = run_id,
                )
                processed += 1

                exit_code = get_scan_exit_code(result)
                if exit_code == 1:
                    had_error = True
                    errors   += 1
                elif result.decision == "BLOCK":
                    had_block = True
                    blocked  += 1
                elif result.decision == "SANITIZE":
                    sanitized += 1
                else:
                    allowed += 1

                if json_output:
                    # JSONL - one object per line, independently parseable
                    # Spec: Section 13.2 (batch JSON output format)
                    sys.stdout.write(json.dumps(scan_result_to_dict(result)) + "\n")
                    sys.stdout.flush()
                elif not quiet and not summary:
                    color = {"BLOCK": "red", "SANITIZE": "yellow", "ALLOW": "green"}.get(
                        result.decision, "white"
                    )
                    click.secho(
                        f"[{processed:>4}] {result.decision:<8} "
                        f"{round(result.confidence, 2):.2f}  "
                        f"{result.trace_id}  "
                        f"{text[:60]}{'...' if len(text) > 60 else ''}",
                        fg=color,
                    )

            except WrapSecRateLimitError:
                print_error(
                    f"Rate limit hit after {processed} prompts. "
                    f"Use --delay to slow requests."
                )
                had_error = True
                break

            except WrapSecError as e:
                click.secho(f"Error on prompt {processed + 1}: {e}", fg="red", err=True)
                had_error = True
                errors   += 1

    # Summary output
    if not quiet and not json_output:
        click.echo("")
        click.echo(f"Results:  {processed} scanned, {skipped} skipped")
        click.secho(f"  BLOCK:    {blocked}",    fg="red"     if blocked    else None)
        click.secho(f"  SANITIZE: {sanitized}",  fg="yellow"  if sanitized  else None)
        click.secho(f"  ALLOW:    {allowed}",    fg="green"   if allowed    else None)
        if errors:
            click.secho(f"  ERRORS:   {errors}", fg="red", err=True)

    # Exit code priority: ERROR (1) > BLOCK (2) > SUCCESS (0)
    # Spec: Section 11.3
    if had_error:
        sys.exit(1)
    elif had_block:
        sys.exit(2)
    else:
        sys.exit(0)
