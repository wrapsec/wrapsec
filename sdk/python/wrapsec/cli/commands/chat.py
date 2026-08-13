# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
wrapsec chat - send a message through the WrapSec proxy to a configured LLM.

Scans input, forwards to the provider, scans output, prints the reply.
Proxy provider must be configured first via the dashboard or PUT /v1/settings/proxy.
"""

from __future__ import annotations

import signal
import sys

import click

from wrapsec.cli._output import print_error, print_json
from wrapsec.cli._spinner import Spinner, should_show_spinner
from wrapsec.client import Client
from wrapsec.config.loader import load_config
from wrapsec.exceptions import WrapSecError


@click.command()
@click.argument("message", required=False)
@click.option(
    "--model", "-m",
    default=None,
    help=(
        "Provider/model string e.g. 'custom/llama-3.1-8b-instruct:free'. "
        "If omitted, uses the default_model configured in proxy settings."
    ),
)
@click.option(
    "--timeout",
    default=None,
    type=int,
    help="Request timeout in seconds (default 90). LLM calls are slower than scans.",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output full JSON response including WrapSec metadata.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show WrapSec security headers alongside the reply.",
)
def chat(
    message:     str | None,
    model:       str | None,
    timeout:     int | None,
    json_output: bool,
    verbose:     bool,
) -> None:
    """Send a message through the WrapSec proxy to the configured LLM.

    MESSAGE can be passed as an argument or piped via stdin.
    The proxy provider must be configured first:
      wrapsec settings set proxy (or via the dashboard Settings page)

    \b
    Exit codes:
      0   Response received
      1   Error (auth, network, provider unreachable)
      2   Input blocked by security policy

    \b
    Examples:
      wrapsec chat "What is 2+2?"
      wrapsec chat --model "custom/llama-3.1-8b-instruct:free" "Hello"
      wrapsec chat --verbose "Explain quantum computing"
      echo "Summarise this document" | wrapsec chat
    """
    if timeout is not None and timeout < 1:
        print_error(f"timeout must be at least 1 second, got {timeout}")
        sys.exit(1)

    if not message:
        if sys.stdin.isatty():
            print_error(
                "No message provided. Pass text as argument or pipe via stdin.\n"
                "Example: wrapsec chat \"your message\"\n"
                "         echo \"your message\" | wrapsec chat"
            )
            sys.exit(1)
        message = sys.stdin.read().strip()

    if not message:
        print_error("Empty message.")
        sys.exit(1)

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
    spinner = Spinner("Waiting for response") if should_show_spinner(json_output, False) else None

    def _sigint_handler(sig: int, frame: object) -> None:
        if spinner:
            spinner.stop()
        sys.exit(1)

    signal.signal(signal.SIGINT, _sigint_handler)

    result = None
    try:
        if spinner:
            spinner.start()

        result = client.chat(message=message, model=model, timeout=timeout)

    except WrapSecError as e:
        if spinner:
            spinner.stop()
        blocked = getattr(e, "status_code", None) == 400
        print_error(str(e))
        sys.exit(2 if blocked else 1)

    except Exception:
        if spinner:
            spinner.stop()
        import logging
        logging.getLogger("wrapsec.cli.chat").exception("Unexpected error")
        print_error("An unexpected error occurred. Check logs for details.")
        sys.exit(1)

    finally:
        if spinner:
            spinner.stop()

    if json_output:
        print_json(result)
        sys.exit(0)

    # Human-readable output
    choices = result.get("choices", [])
    content = choices[0]["message"]["content"] if choices else ""
    click.echo(content)

    if verbose:
        headers = result.get("_wrapsec_headers", {})
        if headers:
            click.echo("")
            click.secho("WrapSec", fg="bright_black", bold=True)
            pairs = [
                ("Input decision",  headers.get("x-wrapsec-input-decision",  "--")),
                ("Output decision", headers.get("x-wrapsec-output-decision", "--")),
                ("Execution",       headers.get("x-wrapsec-execution-status","--")),
                ("Provider",        headers.get("x-wrapsec-provider",        "--")),
                ("Model",           headers.get("x-wrapsec-model",           "--")),
                ("Latency",         (headers["x-wrapsec-latency-ms"] + "ms")
                                    if headers.get("x-wrapsec-latency-ms") else "--"),
                ("Trace ID",        headers.get("x-wrapsec-trace-id",        "--")),
            ]
            for label, value in pairs:
                click.echo(f"  {label:<18} {value}")

    sys.exit(0)
