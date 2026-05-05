# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Thread-safe spinner for CLI output.

Internal module — not part of public API.

Safety requirements per spec Section 12.2:
  1. try/finally MUST call stop() — spinner stops before exceptions propagate
  2. SIGINT handler calls stop() before exit
  3. stop() writes \\r\\033[K (cursor return + clear line) not just \\r
  4. Never shown in --json or --quiet mode
  5. Only shown when sys.stdout.isatty() is True
  6. Platform-aware frames: ASCII fallback for Windows cmd.exe

Spec reference: Section 12.2 (Spinner Rules and Safety)
"""

from __future__ import annotations

import itertools
import os
import sys
import threading
import time


def get_spinner_frames() -> list[str]:
    """
    Return spinner frames appropriate for the current terminal.
    ASCII fallback for Windows cmd.exe (no WT_SESSION or TERM env var).

    Spec: Section 12.2
    """
    if sys.platform == "win32":
        if not (os.environ.get("WT_SESSION") or os.environ.get("TERM")):
            return ["|", "/", "-", "\\"]
    return ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class Spinner:
    """
    Thread-safe spinner. Always use as a context manager or with try/finally.

    Usage (always with try/finally):
        spinner = Spinner("Scanning")
        try:
            spinner.start()
            result = do_work()
        finally:
            spinner.stop()

    Or as context manager:
        with Spinner("Scanning"):
            result = do_work()
    """

    def __init__(self, message: str = "") -> None:
        self._message  = message
        self._frames   = itertools.cycle(get_spinner_frames())
        self._running  = False
        self._lock     = threading.Lock()
        self._thread:  threading.Thread | None = None

    def update(self, message: str) -> None:
        with self._lock:
            self._message = message

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """
        Stop spinner and clear the line.
        Spec: Section 12.2 — clear line properly on all platforms.
        """
        with self._lock:
            self._running = False
        if self._thread:
            self._thread.join(timeout=1)
            self._thread = None
        # On Windows cmd.exe \033[K may not be supported
        # Use \r + spaces to overwrite the line instead
        if sys.platform == "win32" and not (
            os.environ.get("WT_SESSION") or os.environ.get("TERM")
        ):
            sys.stdout.write("\r" + " " * 60 + "\r")
        else:
            sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    def _spin(self) -> None:
        while True:
            with self._lock:
                if not self._running:
                    break
                frame   = next(self._frames)
                message = self._message
            sys.stdout.write(f"\r{frame} {message}...")
            sys.stdout.flush()
            # Use a short sleep with lock release so stop() isn't delayed
            time.sleep(0.08)

    def __enter__(self) -> "Spinner":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


def should_show_spinner(json_output: bool, quiet: bool) -> bool:
    """
    Determine if spinner should be shown.

    Spec: Section 12.2
      show_spinner = sys.stdout.isatty() and not json_output and not quiet
    """
    return sys.stdout.isatty() and not json_output and not quiet
