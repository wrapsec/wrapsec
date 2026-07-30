# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Concrete outbound webhook delivery handler (v1.3.0, 12b.4).

This is the DeliveryHandler injected into workers/webhook_delivery.py. It
turns one queued payload into an HTTP delivery and reconciles the result:

  1. Load the endpoint. Gone or cross-tenant -> dead-letter (no attempt
     row: the FK would dangle). Disabled -> dead-letter with a row.
  2. Build the request. Connector endpoints dispatch through the registry
     (static-token or Entra-bearer auth); generic endpoints HMAC-sign the
     raw body with security.webhook_signing.
  3. POST it via a pooled httpx client with a bounded timeout.
  4. Record one webhook_delivery_attempts row, update the endpoint's
     circuit-breaker timer (record_success / record_failure), and map the
     outcome to SUCCESS / RETRY / DLQ.

Retry policy comes from services.webhooks.retry_schedule (attempt_number
is bumped by the worker on requeue). Permanent failures -- unknown
connector, misconfigured connector, undecryptable secret -- dead-letter
immediately rather than burning the retry schedule on something that
cannot self-heal. Transient failures (5xx, timeouts, token endpoint
blips) retry, then dead-letter when the schedule is exhausted.

send_once() is factored out so the v1.3.1 test-send endpoint can exercise
the exact same build+send path without the queue, attempt-log, or
circuit-breaker side effects.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import httpx

from config.settings import get_settings
from db.repositories.webhook_delivery_attempt import (
    STATUS_DEAD,
    STATUS_FAILED,
    STATUS_SUCCESS,
    WebhookDeliveryAttemptRepository,
)
from db.repositories.webhook_endpoint import WebhookEndpointRepository
from security import webhook_signing
from security.encryption import decrypt
from services.webhooks import retry_schedule
from services.webhooks.connectors import azure_token, registry
from services.webhooks.connectors.registry import AuthKind, UnknownConnectorError
from workers.webhook_delivery import DeliveryOutcome, DeliveryResult

logger = logging.getLogger("wrapsec.webhook_delivery_handler")


def _outcome_success() -> DeliveryOutcome:
    return DeliveryOutcome(result=DeliveryResult.SUCCESS)


def _outcome_retry(delay: int) -> DeliveryOutcome:
    return DeliveryOutcome(result=DeliveryResult.RETRY, retry_in_s=delay)


def _outcome_dlq(reason: str) -> DeliveryOutcome:
    return DeliveryOutcome(result=DeliveryResult.DLQ, dlq_reason=reason)


@dataclass
class SendResult:
    """Outcome of a single build+send, with no queue/DB side effects."""
    ok:               bool
    status_code:      int | None = None
    response_snippet: str | None = None
    duration_ms:      int | None = None
    error:            str | None = None
    # A build/config error that will never succeed on retry (dead-letter now).
    permanent:        bool = False


def _entry_not_expired(entry: dict, now: datetime) -> bool:
    raw = entry.get("expires_at")
    if not isinstance(raw, str):
        return False
    try:
        return datetime.fromisoformat(raw) > now
    except ValueError:
        return False


class WebhookDeliveryHandler:
    """
    Callable delivery handler. Construct once at worker startup (holds a
    pooled httpx client), pass the instance to workers.webhook_delivery.run,
    and aclose() it on shutdown.
    """

    def __init__(self, session_factory, redis, *, timeout_s: int, max_response_bytes: int):
        self._sf                 = session_factory
        self._redis              = redis
        self._max_response_bytes = max_response_bytes
        self._client             = httpx.AsyncClient(timeout=timeout_s)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __call__(self, payload: dict) -> "DeliveryOutcome":
        async with self._sf() as db:
            return await self._handle(db, payload)

    # --- Build (shared with test-send) ---

    async def send_once(
        self, endpoint, event_type: str, body: dict[str, Any], msg_id: str,
    ) -> SendResult:
        """Build and POST one delivery for `endpoint`, returning a
        SendResult. No attempt row, circuit-breaker, or queue effects --
        the queue handler and the v1.3.1 test-send endpoint both use this."""
        try:
            method, url, headers, content = await self._build(endpoint, event_type, body, msg_id)
        except UnknownConnectorError as exc:
            return SendResult(ok=False, error=f"unknown connector: {exc.connector_type}", permanent=True)
        except azure_token.AzureTokenError as exc:
            # Token endpoint blip / throttling -> transient, retry.
            return SendResult(ok=False, error=f"auth: {exc}", permanent=False)
        except (KeyError, ValueError) as exc:
            # Missing connector config or undecryptable secret -> permanent.
            return SendResult(ok=False, error=f"build: {exc}", permanent=True)

        start = time.perf_counter()
        try:
            resp = await self._client.request(method, url, headers=headers, content=content)
        except httpx.HTTPError as exc:
            dur = int((time.perf_counter() - start) * 1000)
            return SendResult(ok=False, duration_ms=dur, error=f"transport: {exc}", permanent=False)

        dur     = int((time.perf_counter() - start) * 1000)
        snippet = (resp.text or "")[: self._max_response_bytes] or None
        ok      = 200 <= resp.status_code < 300
        return SendResult(
            ok               = ok,
            status_code      = resp.status_code,
            response_snippet = snippet,
            duration_ms      = dur,
            error            = None if ok else f"HTTP {resp.status_code}",
        )

    async def _build(self, endpoint, event_type: str, body: dict[str, Any], msg_id: str):
        """Return (method, url, headers, content_bytes) for the endpoint.
        Raises UnknownConnectorError / AzureTokenError / KeyError / ValueError
        for the caller to classify."""
        spec = registry.get_spec(endpoint.connector_type)   # None => generic

        if spec is None:
            return self._build_generic(endpoint, body, msg_id)

        token   = await self._resolve_token(endpoint, spec)
        req     = spec.build_request(
            url        = endpoint.url,
            token      = token,
            event_type = event_type,
            body       = body,
            config     = endpoint.config or {},
        )
        if isinstance(req.json_payload, str):
            content = req.json_payload.encode("utf-8")
        else:
            content = json.dumps(req.json_payload, separators=(",", ":")).encode("utf-8")
        headers = {**(endpoint.headers or {}), **req.headers}
        return req.method, req.url, headers, content

    def _build_generic(self, endpoint, body: dict[str, Any], msg_id: str):
        """Generic HMAC-signed webhook: sign the raw JSON body with the
        active secret plus any non-expired rotation secrets, then POST it."""
        secret_key = get_settings().secret_key
        now        = datetime.utcnow()

        secrets = [decrypt(endpoint.secret_enc, secret_key).encode("utf-8")]
        for entry in endpoint.old_secrets or []:
            if _entry_not_expired(entry, now):
                secrets.append(decrypt(entry["ciphertext"], secret_key).encode("utf-8"))

        content     = json.dumps(body, separators=(",", ":")).encode("utf-8")
        sig_headers = webhook_signing.build_headers(secrets, msg_id, content)
        headers     = {**(endpoint.headers or {}), **sig_headers, "Content-Type": "application/json"}
        return "POST", endpoint.url, headers, content

    async def _resolve_token(self, endpoint, spec) -> str:
        """Resolve the connector's auth material into a header token."""
        secret_key = get_settings().secret_key
        if spec.auth_kind is AuthKind.STATIC_TOKEN:
            return decrypt(endpoint.secret_enc, secret_key)
        # ENTRA_BEARER: acquire (cached) bearer from the app-registration creds.
        cfg = endpoint.config or {}
        return await azure_token.get_access_token(
            self._redis,
            tenant_id     = cfg["tenant_id"],
            client_id     = cfg["client_id"],
            client_secret = decrypt(endpoint.secret_enc, secret_key),
            cloud         = cfg.get("cloud", "public"),
        )

    # --- Queue delivery (attempt row + circuit breaker + outcome) ---

    async def _handle(self, db, payload: dict) -> "DeliveryOutcome":
        endpoint_id    = UUID(str(payload["endpoint_id"]))
        tenant_id      = UUID(str(payload["tenant_id"]))
        msg_id         = str(payload["msg_id"])
        event_type     = str(payload["event_type"])
        attempt_number = int(payload.get("attempt_number", 1))
        body           = payload.get("body") or {}

        ep_repo  = WebhookEndpointRepository(db)
        att_repo = WebhookDeliveryAttemptRepository(db)
        endpoint = await ep_repo.get_by_id(endpoint_id)

        # Endpoint vanished or belongs to another tenant: no valid FK target
        # for an attempt row, so dead-letter with a log instead.
        if endpoint is None or str(endpoint.tenant_id) != str(tenant_id):
            reason = "endpoint_deleted" if endpoint is None else "endpoint_tenant_mismatch"
            logger.warning("webhook delivery %s msg_id=%s: %s", reason, msg_id, endpoint_id)
            return _outcome_dlq(reason)

        if endpoint.disabled:
            await att_repo.record(
                endpoint_id=endpoint_id, tenant_id=tenant_id, msg_id=msg_id,
                url=endpoint.url, event_type=event_type, attempt_number=attempt_number,
                status=STATUS_DEAD, error_message="endpoint_disabled",
            )
            await db.commit()
            return _outcome_dlq("endpoint_disabled")

        result = await self.send_once(endpoint, event_type, body, msg_id)

        if result.ok:
            await ep_repo.record_success(endpoint_id=endpoint_id)
            await att_repo.record(
                endpoint_id=endpoint_id, tenant_id=tenant_id, msg_id=msg_id,
                url=endpoint.url, event_type=event_type, attempt_number=attempt_number,
                status=STATUS_SUCCESS, http_status_code=result.status_code,
                response_snippet=result.response_snippet, duration_ms=result.duration_ms,
            )
            await db.commit()
            return _outcome_success()

        # Failure. record_failure advances the circuit-breaker timer either way.
        await ep_repo.record_failure(endpoint_id=endpoint_id)

        # Permanent (unknown/misconfigured connector, bad secret) or retries
        # exhausted -> dead-letter now.
        delay = None if result.permanent else retry_schedule.next_retry_delay(attempt_number)
        if delay is None:
            reason = "permanent_error" if result.permanent else "retries_exhausted"
            await att_repo.record(
                endpoint_id=endpoint_id, tenant_id=tenant_id, msg_id=msg_id,
                url=endpoint.url, event_type=event_type, attempt_number=attempt_number,
                status=STATUS_DEAD, http_status_code=result.status_code,
                response_snippet=result.response_snippet, duration_ms=result.duration_ms,
                error_message=result.error,
            )
            await db.commit()
            return _outcome_dlq(reason)

        next_at = datetime.utcnow() + timedelta(seconds=delay)
        await att_repo.record(
            endpoint_id=endpoint_id, tenant_id=tenant_id, msg_id=msg_id,
            url=endpoint.url, event_type=event_type, attempt_number=attempt_number,
            status=STATUS_FAILED, http_status_code=result.status_code,
            response_snippet=result.response_snippet, duration_ms=result.duration_ms,
            error_message=result.error, next_attempt_at=next_at,
        )
        await db.commit()
        return _outcome_retry(delay)
