# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Outbox email delivery worker (v1.8.3).

A PostgreSQL polling worker: it atomically claims a batch of due rows from
email_outbox (SELECT ... FOR UPDATE SKIP LOCKED, via the repository), sends each
through the configured EmailProvider under a concurrency cap, and records the
outcome. It deliberately uses PostgreSQL rather than the Redis Streams webhook
queue because the enqueue must be atomic with the business transaction that
triggered the notification.

Retry policy is the shared webhook retry schedule (services.webhooks.
retry_schedule): a transient failure reschedules the row by pushing its
available_at into the future; a permanent failure or exhausted retries marks it
failed. There is no cross-message circuit breaker -- unlike the many-endpoint
webhook system, email targets a single SMTP provider and the per-message backoff
plus available_at gating already bound the load on a struggling server.

A stable Message-ID is derived from the outbox row id, so a receiver can dedupe
a message that is retried after the worker crashed between provider-accept and
the status write. This is best-effort de-duplication, not an exactly-once claim
(see the plan, section 13).

Lifecycle mirrors the webhook worker: a long-running loop cancelled via a
stop_event from the FastAPI lifespan, draining in-flight sends before returning.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from sqlalchemy.ext.asyncio import async_sessionmaker

from db.repositories.email_outbox import EmailOutboxRepository
from services.email.provider import (
    EmailProvider,
    OutgoingEmail,
    PermanentEmailError,
    TransientEmailError,
)
from services.time import utc_now
from services.webhooks.retry_schedule import next_retry_delay

logger = logging.getLogger("wrapsec.email_worker")


@dataclass(frozen=True)
class _Claimed:
    """Snapshot of a claimed row, detached from the claim session so its fields
    are safe to read after that session commits and closes."""
    id:            UUID
    recipient:     str
    subject:       str
    body_text:     str
    body_html:     str | None
    attempt_count: int
    trace_id:      str | None


def _message_id(row_id: UUID, from_addr: str) -> str:
    """Stable RFC 5322 Message-ID per outbox row (same across retries)."""
    domain = from_addr.partition("@")[2] or "wrapsec.local"
    return f"<{row_id}@{domain}>"


async def _claim(session_factory: async_sessionmaker, batch: int) -> list[_Claimed]:
    """Claim a batch and commit the 'sending' transition (releasing row locks)
    before any send happens. Returns detached snapshots."""
    async with session_factory() as db:
        repo = EmailOutboxRepository(db)
        rows = await repo.claim_batch(limit=batch)
        claimed = [
            _Claimed(
                id            = r.id,
                recipient     = r.recipient,
                subject       = r.subject,
                body_text     = r.body_text,
                body_html     = r.body_html,
                attempt_count = r.attempt_count,
                trace_id      = r.trace_id,
            )
            for r in rows
        ]
        await db.commit()
        return claimed


async def _process_one(
    session_factory: async_sessionmaker,
    provider:        EmailProvider,
    from_addr:       str,
    from_name:       str,
    row:             _Claimed,
    sem:             asyncio.Semaphore,
    max_attempts:    int,
) -> None:
    """Send one claimed row and record the outcome in its own transaction, so
    one row's failure never rolls back another's status write."""
    async with sem:
        message = OutgoingEmail(
            to_addr    = row.recipient,
            subject    = row.subject,
            text_body  = row.body_text,
            html_body  = row.body_html,
            from_addr  = from_addr,
            from_name  = from_name,
            message_id = _message_id(row.id, from_addr),
        )
        attempt = row.attempt_count + 1

        try:
            provider_message_id = await provider.send(message)
        except PermanentEmailError as exc:
            await _mark_failed(session_factory, row.id, attempt, f"permanent: {exc}")
            logger.warning("email permanent failure id=%s attempt=%d: %s", row.id, attempt, exc)
            return
        except TransientEmailError as exc:
            await _retry_or_fail(session_factory, row.id, attempt, str(exc), max_attempts)
            return
        except Exception as exc:
            logger.exception("email send raised unexpectedly id=%s", row.id)
            await _retry_or_fail(session_factory, row.id, attempt, f"unexpected: {exc}", max_attempts)
            return

        await _mark_accepted(session_factory, row.id, attempt, provider_message_id)
        logger.info(
            "email provider_accepted id=%s attempt=%d trace_id=%s", row.id, attempt, row.trace_id
        )


async def _retry_or_fail(
    session_factory: async_sessionmaker,
    row_id:          UUID,
    attempt:         int,
    error:           str,
    max_attempts:    int,
) -> None:
    # Exhausted when we hit the configured attempt ceiling OR the fixed backoff
    # schedule has no further interval. The configured max can only cap earlier,
    # never beyond the schedule (settings clamps it to MAX_ATTEMPTS).
    delay = next_retry_delay(attempt)
    if attempt >= max_attempts or delay is None:
        await _mark_failed(session_factory, row_id, attempt, f"retries exhausted: {error}")
        logger.warning("email retries exhausted id=%s attempt=%d: %s", row_id, attempt, error)
        return
    available_at = utc_now() + timedelta(seconds=delay)
    async with session_factory() as db:
        await EmailOutboxRepository(db).reschedule(
            row_id=row_id, attempt_count=attempt, available_at=available_at, error=error
        )
        await db.commit()
    logger.info("email transient failure id=%s attempt=%d retry_in=%ds", row_id, attempt, delay)


async def _mark_accepted(
    session_factory: async_sessionmaker,
    row_id:          UUID,
    attempt:         int,
    provider_message_id: str | None,
) -> None:
    async with session_factory() as db:
        await EmailOutboxRepository(db).mark_accepted(
            row_id=row_id, attempt_count=attempt, provider_message_id=provider_message_id
        )
        await db.commit()


async def _mark_failed(
    session_factory: async_sessionmaker,
    row_id:          UUID,
    attempt:         int,
    error:           str,
) -> None:
    async with session_factory() as db:
        await EmailOutboxRepository(db).mark_failed(row_id=row_id, attempt_count=attempt, error=error)
        await db.commit()


async def run(
    session_factory: async_sessionmaker,
    provider:        EmailProvider,
    from_addr:       str,
    from_name:       str,
    *,
    stop_event:      asyncio.Event | None = None,
    poll_seconds:    int = 10,
    batch:           int = 20,
    concurrency:     int = 5,
) -> None:
    """
    Worker main loop. Runs until `stop_event` is set (or forever if None).

    Each iteration claims a batch and sends it concurrently (bounded by
    `concurrency`). When nothing is due it waits up to `poll_seconds`,
    interruptible by the stop event for prompt shutdown.
    """
    if stop_event is None:
        stop_event = asyncio.Event()

    sem: asyncio.Semaphore = asyncio.Semaphore(concurrency)
    logger.info("email worker started: batch=%d concurrency=%d poll=%ds", batch, concurrency, poll_seconds)

    try:
        while not stop_event.is_set():
            try:
                claimed = await _claim(session_factory, batch)
            except Exception:
                logger.exception("email claim failed, backing off 5s")
                await _sleep_or_stop(stop_event, 5)
                continue

            if not claimed:
                await _sleep_or_stop(stop_event, poll_seconds)
                continue

            # Read the configured attempt ceiling once per batch (cheap PK
            # lookup) so a mid-run settings change takes effect promptly.
            from services.email.settings import get_email_settings
            async with session_factory() as db:
                max_attempts = (await get_email_settings(db)).max_attempts

            await asyncio.gather(
                *(_process_one(session_factory, provider, from_addr, from_name, row, sem, max_attempts) for row in claimed),
                return_exceptions=True,
            )
    finally:
        logger.info("email worker stopped")


async def _sleep_or_stop(stop_event: asyncio.Event, seconds: float) -> None:
    """Wait up to `seconds`, returning early if the stop event is set."""
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        return
