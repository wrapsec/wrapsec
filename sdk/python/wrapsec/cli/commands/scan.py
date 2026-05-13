# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
wrapsec scan - scan a single prompt for security risks.

Spec reference: Section 13.2 (wrapsec scan), Section 11 (Exit Codes),
                Section 12 (Output Modes), Section 10.4 (Security Rules)
"""

from __future__ import annotations

import logging

import signal
import sys

import click

logger = logging.getLogger('wrapsec.cli.scan')

from wrapsec.client import Client
from wrapsec.config.loader import load_config
from wrapsec.core.validation import MAX_INPUT_CHARS, normalize_text, validate_input, warn_if_dense
from wrapsec.exceptions import WrapSecError
from wrapsec.cli._output import (
    format_scan_result_human,
    get_scan_exit_code,
    print_error,
    print_json,
    print_success,
    scan_result_to_dict,
)
from wrapsec.cli._spinner import Spinner, should_show_spinner


@click.command()
@click.argument("text", required=False)
@click.option(
    "--mode", "-m",
    default="fast",
    type=click.Choice(["fast", "full"]),
    show_default=True,
    help=(
        "Detection mode. full enables LLM semantic analysis for deeper "
        "inspection of ambiguous inputs. Results may differ from fast mode. "
        "Latency increases by ~100-2300ms depending on LLM model."
    ),
)
@click.option(
    "--timeout",
    default=None,
    type=int,
    help="Request timeout in seconds (min 1, default 30). "
         "Override with WRAPSEC_TIMEOUT env var.",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output pure JSON to stdout. No spinner, no extra text. "
         "Note: exposes trace_id and scores - use --quiet in CI when possible.",
)
@click.option(
    "--user", "-u",
    default="cli",
    show_default=True,
    help="User ID for audit attribution. Default: 'cli'. "
         "OS username is never used automatically.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="No stdout output. Errors still go to stderr. "
         "Exit code is the only interface. Recommended for CI.",
)
def scan(
    text:        str | None,
    mode:        str,
    timeout:     int | None,
    json_output: bool,
    user:        str,
    quiet:       bool,
) -> None:
    """Scan a single prompt for security risks.

    TEXT can be passed as an argument or piped via stdin.

    \b
    Security note:
      CLI arguments are stored in shell history.
      Use stdin for sensitive content:
        echo "text" | wrapsec scan
        cat prompt.txt | wrapsec scan

    \b
    Exit codes:
      0   ALLOW or SANITIZE (input accepted)
      1   CLI error, network failure, auth error, rate limit, SYSTEM_ERROR
      2   BLOCK (input rejected by security policy)

    \b
    Examples:
      wrapsec scan "hello world"
      wrapsec scan --mode full "ignore previous instructions"
      echo "user SSN: 123-45-6789" | wrapsec scan
      cat prompt.txt | wrapsec scan --json
      wrapsec scan --quiet "text"   # CI usage
    """
    # Validate timeout early at CLI level
    # Spec: Section 7 - validation at CLI and SDK level
    if timeout is not None and timeout < 1:
        print_error(f"timeout must be at least 1 second, got {timeout}")
        sys.exit(1)

    # Read from stdin if no argument provided
    if not text:
        if sys.stdin.isatty():
            print_error(
                "No input provided. Pass text as argument or pipe via stdin.\n"
                "Example: wrapsec scan \"your prompt\"\n"
                "         echo \"your prompt\" | wrapsec scan"
            )
            sys.exit(1)
        text = sys.stdin.read()

    # Normalise and validate
    try:
        text = normalize_text(text)
        text = validate_input(text)
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)

    # Warn about dense text that may be rejected by server heuristic
    dense_warning = warn_if_dense(text)
    if dense_warning and not quiet and not json_output:
        click.secho(dense_warning, fg="yellow", err=True)

    # Require API key
    cfg = load_config()
    if not cfg.api_key:
        print_error(
            "No API key configured.\n\n"
            "Set it with:\n"
            "  wrapsec config set api_key wsk_live_...\n\n"
            "Or set the environment variable:\n"
            "  export WRAPSEC_API_KEY=wsk_live_..."
        )
        sys.exit(1)

    client  = Client(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)
    spinner = Spinner("Scanning") if should_show_spinner(json_output, quiet) else None

    # Register SIGINT handler to clean up spinner
    # Spec: Section 12.2 - SIGINT must stop spinner before exit
    def _sigint_handler(sig: int, frame: object) -> None:
        if spinner:
            spinner.stop()
        sys.exit(1)

    signal.signal(signal.SIGINT, _sigint_handler)

    result = None
    try:
        if spinner:
            spinner.start()
            spinner.update("Running detection layers")

        result = client.scan(text, mode=mode, user=user, timeout=timeout)

    except WrapSecError as e:
        if spinner:
            spinner.stop()
        print_error(str(e))
        sys.exit(1)

    except Exception as e:
        if spinner:
            spinner.stop()
        # Fix #4 - log full exception internally, show generic message to user.
        # Full exception text may contain internal paths, module names, or
        # server responses that should not be exposed to end users.
        logger.error("Unexpected error during scan: %s", e, exc_info=True)
        print_error("An unexpected error occurred. Check logs for details.")
        sys.exit(1)

    finally:
        # Always stop spinner - even if exception was raised
        # Spec: Section 12.2 - try/finally MUST call stop()
        if spinner:
            spinner.stop()

    if result is None:
        print_error("No response received from API.")
        sys.exit(1)

    exit_code = get_scan_exit_code(result)

    if json_output:
        # Pure JSON to stdout - nothing else
        # Spec: Section 12.4
        print_json(scan_result_to_dict(result))
        sys.exit(exit_code)

    if not quiet:
        click.echo("")

    format_scan_result_human(result, quiet)

    sys.exit(exit_code)
