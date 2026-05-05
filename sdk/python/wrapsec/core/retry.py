# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Retry logic — exponential backoff for transient failures.

ALL retry logic lives here. CLI commands never retry.
CLI handles only the final exception after retries are exhausted.

Spec reference: Section 9 (Retry Logic), Section 15 (HTTP Error Handling)

Retried (up to 3 attempts):
  HTTP 5xx, Timeout, ConnectionError

Never retried:
  HTTP 401, 403, 404, 413, 422 — permanent client errors
  HTTP 429                      — retrying worsens rate limiting
  BLOCK decision                — not an error

Backoff schedule:
  Attempt 1: immediate
  Attempt 2: wait 1s
  Attempt 3: wait 2s
  After 3 failures: raise WrapSecSystemError
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable, TypeVar

from wrapsec.exceptions import WrapSecSystemError

logger = logging.getLogger("wrapsec.retry")

T = TypeVar("T")

# Backoff delays in seconds between attempts (0 = immediate first attempt)
BACKOFF_SCHEDULE: tuple[float, ...] = (0, 1, 2)
MAX_ATTEMPTS = len(BACKOFF_SCHEDULE)


def is_retryable_status(status_code: int) -> bool:
    """
    Returns True if the HTTP status code warrants a retry.
    Only 5xx errors are retried — client errors are permanent.

    Spec: Section 9, Section 15
    """
    return status_code >= 500


def with_retry(fn: Callable[[], T], operation: str = "request") -> T:
    """
    Execute fn() with exponential backoff retry for transient failures.

    fn must raise one of:
      - WrapSecSystemError  → retried
      - Any other exception → not retried, propagated immediately

    Spec: Section 9 — all retry logic lives exclusively in core/retry.py
    """
    last_error: Exception | None = None

    for attempt, delay in enumerate(BACKOFF_SCHEDULE):
        if delay > 0:
            logger.debug(f"Retry {attempt}/{MAX_ATTEMPTS - 1} for {operation} — waiting {delay}s")
            time.sleep(delay)

        try:
            return fn()
        except WrapSecSystemError as e:
            last_error = e
            if attempt < MAX_ATTEMPTS - 1:
                logger.warning(
                    f"{operation} failed (attempt {attempt + 1}/{MAX_ATTEMPTS}): {e.message}"
                )
            else:
                logger.error(
                    f"{operation} failed after {MAX_ATTEMPTS} attempts: {e.message}"
                )
        # All other exceptions propagate immediately — never retry auth,
        # rate limit, or validation errors
        except Exception:
            raise

    raise last_error or WrapSecSystemError(
        f"Operation failed after {MAX_ATTEMPTS} attempts"
    )


async def with_retry_async(fn: Callable[[], Awaitable[T]], operation: str = "request") -> T:
    """
    Async version of with_retry for use with async_client.py.

    Spec: Section 9 — retry logic shared by sync and async clients
    """
    last_error: Exception | None = None

    for attempt, delay in enumerate(BACKOFF_SCHEDULE):
        if delay > 0:
            logger.debug(f"Retry {attempt}/{MAX_ATTEMPTS - 1} for {operation} — waiting {delay}s")
            await asyncio.sleep(delay)

        try:
            return await fn()
        except WrapSecSystemError as e:
            last_error = e
            if attempt < MAX_ATTEMPTS - 1:
                logger.warning(
                    f"{operation} failed (attempt {attempt + 1}/{MAX_ATTEMPTS}): {e.message}"
                )
            else:
                logger.error(
                    f"{operation} failed after {MAX_ATTEMPTS} attempts: {e.message}"
                )
        except Exception:
            raise

    raise last_error or WrapSecSystemError(
        f"Operation failed after {MAX_ATTEMPTS} attempts"
    )
