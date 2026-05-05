# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Shared output helpers for CLI commands.

Internal module — not part of public API.

All errors go to stderr. Normal output goes to stdout.
Spec: Section 10.4 rule 7
"""

from __future__ import annotations

import json
import sys

import click

from wrapsec.models import ScanResult


def print_error(message: str) -> None:
    """Print error message to stderr. Never to stdout."""
    click.secho(f"❌ {message}", fg="red", err=True)


def print_warning(message: str) -> None:
    """Print warning to stderr."""
    click.secho(f"⚠ {message}", fg="yellow", err=True)


def print_success(message: str) -> None:
    """Print success message to stdout."""
    click.secho(f"✔ {message}", fg="green")


def print_json(data: object) -> None:
    """
    Print pure JSON to stdout. Nothing else — no prefix, no suffix.
    Spec: Section 12.4 (JSON mode contract)
    """
    click.echo(json.dumps(data, indent=2, default=str))


def format_scan_result_human(result: ScanResult, quiet: bool) -> None:
    """
    Print a ScanResult in human-readable format.

    Rules per spec:
      - Confidence rounded to 1 decimal (Section 10.4 rule 8)
      - sanitized_input never shown by default (Section 10.4 rule 4)
      - SYSTEM_ERROR triggers explicit warning (Section 12.5)
      - Exit code 1 for SYSTEM_ERROR regardless of decision (Section 11.2)

    Spec: Section 12.5, Section 10.4
    """
    if quiet:
        return

    color = {
        "BLOCK":    "red",
        "SANITIZE": "yellow",
        "ALLOW":    "green",
    }.get(result.decision, "white")

    click.secho(f"Decision:   {result.decision}", fg=color, bold=True)
    click.echo(f"Reason:     {result.primary_reason}")
    click.echo(f"Confidence: {round(result.confidence, 1)} ({result.confidence_band})")
    click.echo(f"Trace ID:   {result.trace_id}")

    if result.threats:
        click.echo(f"Threats:    {', '.join(result.threats)}")

    if result.decision == "SANITIZE":
        # Never show sanitized_input content — just inform that redaction occurred
        # Spec: Section 10.4 rule 4
        click.echo("Sanitized:  Input contained PII and was sanitized.")

    if result.is_system_error:
        # Spec: Section 12.5 — explicit warning for SYSTEM_ERROR
        print_warning(
            f"Infrastructure error — detection did not complete. "
            f"This result may be unreliable. "
            f"Contact your WrapSec administrator and reference trace ID: {result.trace_id}",
        )


def scan_result_to_dict(result: ScanResult) -> dict:
    """Convert ScanResult to dict for JSON output."""
    return {
        "decision":        result.decision,
        "primary_reason":  result.primary_reason,
        "confidence":      result.confidence,
        "confidence_band": result.confidence_band,
        "trace_id":        result.trace_id,
        "threats":         result.threats,
        "latency_ms":      result.latency_ms,
        "sanitized_input": result.sanitized_input,
    }


def get_scan_exit_code(result: ScanResult) -> int:
    """
    Determine CLI exit code from a ScanResult.

    SYSTEM_ERROR always exits 1 regardless of decision field.
    BLOCK exits 2.
    ALLOW or SANITIZE exits 0.

    Spec: Section 11.1, Section 11.2
    """
    if result.is_system_error:
        return 1
    if result.decision == "BLOCK":
        return 2
    return 0
