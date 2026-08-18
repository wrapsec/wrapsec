# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Admin CRUD + secret rotation for outbound webhook endpoints (v1.3.0).

Security model:

  * All routes require ADMIN role. Webhook configuration is not
    developer surface -- setting a destination URL and signing secret
    materially changes what leaves the platform.

  * The plaintext signing secret is returned in exactly two responses
    and nowhere else: the create response (once, at row insert time)
    and the rotate-secret response (once, at rotation time). GET and
    LIST always return `secret_masked` -- never `secret`. There is no
    GET /secret endpoint. If an admin loses the plaintext, they
    rotate.

  * Every secret-returning response emits a `webhook_secret_rotated`
    or `webhook_endpoint_created` admin_event so the fact that
    plaintext left the server is always audit-visible.

  * URL is SSRF-validated with the shared validator before write. A
    webhook URL that resolves to a private/loopback/metadata address
    would let a compromised admin use the delivery worker as an
    egress SSRF primitive.

  * Cross-tenant access returns 404, not 403 -- 403 would confirm the
    endpoint id exists on another tenant, letting an authenticated
    attacker enumerate ids across tenants.

  * Update() at the repo layer silently drops secret_enc,
    old_secrets, disabled, first_failure_at, tenant_id -- but this
    layer also does not accept those fields in the request schema, so
    a malicious PUT never reaches the repo with them.

Deliberately out of scope for v1.3.0:
  * headers / rate_limit fields on the model -- no downstream
    consumer reads them yet; ship when the delivery handler does.
  * Test-delivery endpoint -- SIEM connectors (#9-#12) effectively
    provide this in a real integration.
  * GET plaintext secret -- add in v1.3.1 alongside the dashboard UI
    so any expose-secret action is at least browser-visible.
"""

from __future__ import annotations

import logging
import secrets as pysecrets
import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import require_admin
from api.v1.dependencies.db import get_db
from api.v1.middleware.auth import get_client_ip
from config.settings import get_settings
from db.models import WebhookEndpointModel
from db.repositories.admin_event import AdminEventRepository
from db.repositories.webhook_endpoint import WebhookEndpointRepository
from domain.entities.principal import Principal
from domain.enums import AdminEventAction
from errors.exceptions import NotFoundError, ValidationError
from services.time import to_iso_z, utc_now
from services.webhooks.emitter import EVENT_BLOCKED, EVENT_SANITIZED

# The only event types WrapSec emits today (BLOCK / SANITIZE gateway decisions).
_ALLOWED_EVENT_TYPES = {EVENT_BLOCKED, EVENT_SANITIZED}


def _validate_event_types(v: list[str] | None) -> list[str] | None:
    if v is None:
        return v
    bad = [e for e in v if e not in _ALLOWED_EVENT_TYPES]
    if bad:
        raise ValueError(
            f"unknown event_types: {', '.join(bad)}; "
            f"allowed: {', '.join(sorted(_ALLOWED_EVENT_TYPES))}"
        )
    return v
from cache.redis_client import get_redis
from security import webhook_ssrf
from security.encryption import encrypt, mask
from security.url_validator import validate_llm_base_url
from services.webhooks.connectors import registry
from services.webhooks.connectors.form_schema import connector_forms
from services.webhooks.delivery_handler import WebhookDeliveryHandler

logger = logging.getLogger("wrapsec.webhooks_admin")

router = APIRouter()


# Length of a freshly generated signing secret, in bytes. 32 bytes ==
# 256 bits, matches HMAC-SHA256 block size, base64-url-encodes to a
# ~43 char string that fits comfortably in receiver-side env vars.
_SECRET_BYTES = 32

# Default grace window when a rotation does not specify one. Long
# enough for a receiver to redeploy verifier code across a typical
# release cycle, short enough that a compromised secret does not
# remain valid for weeks.
_DEFAULT_ROTATION_GRACE_HOURS = 24


# ─── Schemas ────────────────────────────────────────────────────────

class WebhookCreateSchema(BaseModel):
    url:            str        = Field(max_length=2048)
    description:    str        | None = Field(None, max_length=1000)
    event_types:    list[str]  | None = None
    # NULL connector_type => generic HMAC webhook (signing secret generated
    # server-side). A connector slug routes to a SIEM connector: `secret` is
    # the customer's ingest token/key and `config` its per-endpoint options.
    connector_type: str        | None = None
    config:         dict       | None = None
    secret:         str        | None = None

    @field_validator("event_types")
    @classmethod
    def _valid_event_types(cls, v):
        return _validate_event_types(v)

    @field_validator("url")
    @classmethod
    def _url_must_be_ssrf_safe(cls, v: str) -> str:
        # Reuses the shared SSRF validator (same one gating LLM
        # provider URLs). Blocks localhost/metadata/private-range
        # targets so a compromised admin cannot repurpose the
        # delivery worker as an egress SSRF primitive. SIEM ingest hosts
        # are public HTTPS, so this holds for connector endpoints too.
        # The SSRF-safe rules are still enforced (private/internal/metadata
        # destinations are rejected). Only the user-facing wording is generic:
        # the client sees INVALID_URL, never the internal reason (no leak).
        try:
            return validate_llm_base_url(v)
        except ValueError as exc:
            logger.warning("webhook url rejected (ssrf-safe check): %s", exc)
            raise PydanticCustomError(
                "invalid_url", "URL is not an allowed public destination"
            ) from None

    @model_validator(mode="after")
    def _validate_connector(self) -> WebhookCreateSchema:
        if self.connector_type is None:
            # Generic webhook: the signing secret is generated server-side.
            if self.secret is not None:
                raise ValueError("secret is generated server-side for generic webhooks")
            if self.config is not None:
                raise ValueError("config applies only to connector endpoints")
            return self
        if not registry.is_known(self.connector_type):
            raise ValueError(f"unknown connector_type: {self.connector_type!r}")
        if not self.secret:
            raise ValueError(
                f"secret (ingest token) is required for connector_type {self.connector_type!r}"
            )
        missing = registry.missing_config(self.connector_type, self.config)
        if missing:
            raise ValueError(
                f"connector_type {self.connector_type!r} requires config keys: "
                f"{', '.join(missing)}"
            )
        return self


class WebhookUpdateSchema(BaseModel):
    url:         str        | None = Field(None, max_length=2048)
    description: str        | None = Field(None, max_length=1000)
    event_types: list[str]  | None = None
    # Per-connector options are editable; connector_type is immutable after
    # create (it governs how secret_enc is interpreted) and is dropped by the
    # repository if passed.
    config:      dict       | None = None

    @field_validator("event_types")
    @classmethod
    def _valid_event_types(cls, v):
        return _validate_event_types(v)

    @field_validator("url")
    @classmethod
    def _url_must_be_ssrf_safe(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            return validate_llm_base_url(v)
        except ValueError as exc:
            logger.warning("webhook url rejected (ssrf-safe check): %s", exc)
            raise PydanticCustomError(
                "invalid_url", "URL is not an allowed public destination"
            ) from None


class WebhookRotateSchema(BaseModel):
    grace_hours: int = Field(_DEFAULT_ROTATION_GRACE_HOURS, ge=1, le=168)


# ─── Formatting helpers ─────────────────────────────────────────────

def _health_status(ep: WebhookEndpointModel) -> str:
    """Computed lifecycle status for the dashboard health chip:
    paused (admin disabled a healthy endpoint), auto_disabled (circuit breaker
    retired a failing one), failing (in a failure window), or active. Paused vs
    auto_disabled is told apart by first_failure_at: the breaker only disables
    endpoints that carry a failure timestamp, a manual pause leaves it clear."""
    if ep.disabled:
        return "auto_disabled" if ep.first_failure_at is not None else "paused"
    if ep.first_failure_at is not None:
        return "failing"
    return "active"


def _format_masked(ep: WebhookEndpointModel) -> dict:
    """Read-side projection. NEVER contains plaintext secret or the
    ciphertext of the current or old secrets -- only a mask derived
    from the ciphertext string so operators can spot rotations
    without exposing key material. `config` holds non-secret connector
    options (the client secret lives in secret_enc, never here)."""
    return {
        "id":                str(ep.id),
        "tenant_id":         str(ep.tenant_id),
        "url":               ep.url,
        "description":       ep.description,
        "event_types":       ep.event_types,
        "connector_type":    ep.connector_type,
        "config":            ep.config,
        "disabled":          ep.disabled,
        "status":            _health_status(ep),
        "first_failure_at":  to_iso_z(ep.first_failure_at) if ep.first_failure_at else None,
        "secret_masked":     mask(ep.secret_enc or ""),
        "created_at":        to_iso_z(ep.created_at) if ep.created_at else None,
        "updated_at":        to_iso_z(ep.updated_at) if ep.updated_at else None,
    }


def _format_with_plaintext(ep: WebhookEndpointModel, plaintext_secret: str) -> dict:
    """Write-side projection used exactly twice: create response and
    rotate response. Returns the plaintext secret so the admin can
    copy it into the receiver's verifier config. This is the ONLY
    place plaintext secret leaves the server."""
    body = _format_masked(ep)
    body["secret"] = plaintext_secret
    return body


def _actor_user_id(principal: Principal) -> uuid.UUID | None:
    """Extract the user UUID from a Principal's id (`user:<uuid>`).
    Returns None for non-user principals so admin_events logging is
    skipped cleanly rather than crashing on API-key auth paths."""
    raw = str(principal.id)
    if not raw.startswith("user:"):
        return None
    try:
        return uuid.UUID(raw.replace("user:", ""))
    except ValueError:
        return None


async def _log_admin_event(
    db:         AsyncSession,
    request:    Request,
    principal:  Principal,
    tenant_id:  uuid.UUID,
    action:     AdminEventAction,
    metadata:   dict,
) -> None:
    """Best-effort admin_event write. Never raises to the caller --
    audit-log failure MUST NOT roll back a successful admin action."""
    actor = _actor_user_id(principal)
    if actor is None:
        return
    try:
        repo = AdminEventRepository(db)
        await repo.insert(
            tenant_id     = tenant_id,
            actor_user_id = actor,
            action        = action,
            metadata      = metadata,
            ip_address    = get_client_ip(request),
            user_agent    = request.headers.get("user-agent"),
        )
        await db.commit()
    except Exception as exc:
        logger.warning("webhook admin_event log failed: %s", exc)


async def _reject_bad_egress(url: str) -> None:
    """Fail-fast create/update guard. Hard-blocks a destination that resolves
    to a private/internal address, requires https, and blocks metadata hosts.
    A transient DNS failure is tolerated at write time -- the connect-time
    guard in delivery_handler.send_once is authoritative and re-checks on
    every delivery, covering DNS repointing after create."""
    try:
        await webhook_ssrf.check_egress(url)
    except webhook_ssrf.WebhookEgressBlocked as exc:
        if exc.reason == "dns_resolution_failed":
            return
        raise ValidationError(f"webhook destination rejected: {exc.reason}") from None


async def _get_owned_endpoint_or_404(
    repo:        WebhookEndpointRepository,
    endpoint_id: uuid.UUID,
    tenant_id:   uuid.UUID,
) -> WebhookEndpointModel:
    """Load an endpoint and confirm it belongs to the caller's tenant.
    Returns 404 on both missing rows and rows from other tenants so
    the two cases are indistinguishable to the caller (no
    cross-tenant id enumeration)."""
    ep = await repo.get_by_id(endpoint_id)
    if ep is None or ep.tenant_id != tenant_id:
        raise NotFoundError("webhook_endpoint", str(endpoint_id))
    return ep


# ─── Routes ─────────────────────────────────────────────────────────

@router.post("")
async def create_webhook(
    body:      WebhookCreateSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Create a new webhook endpoint on the caller's tenant. The response
    body includes the freshly generated plaintext signing secret as
    `secret` -- copy it into the receiver's verifier config on first
    read, because subsequent GET/LIST responses only show the mask.
    """
    tenant_id = uuid.UUID(request.state.tenant_id)
    await _reject_bad_egress(body.url)

    # Generic webhook: generate a signing secret and return it once. Connector
    # endpoint: encrypt the customer-supplied ingest token and never echo it
    # back (the customer already holds it).
    if body.connector_type is None:
        plaintext_secret = pysecrets.token_urlsafe(_SECRET_BYTES)
        secret_enc       = encrypt(plaintext_secret, get_settings().secret_key)
    else:
        plaintext_secret = None
        assert body.secret is not None  # required for connector_type by the schema validator
        secret_enc       = encrypt(body.secret, get_settings().secret_key)

    repo = WebhookEndpointRepository(db)
    ep   = await repo.create(
        tenant_id      = tenant_id,
        url            = body.url,
        secret_enc     = secret_enc,
        description    = body.description,
        event_types    = body.event_types,
        connector_type = body.connector_type,
        config         = body.config,
    )
    await db.commit()

    await _log_admin_event(
        db, request, principal, tenant_id,
        AdminEventAction.WEBHOOK_ENDPOINT_CREATED,
        {
            "endpoint_id":    str(ep.id),
            "url":            ep.url,
            "event_types":    ep.event_types,
            "connector_type": ep.connector_type,
        },
    )

    content = (
        _format_with_plaintext(ep, plaintext_secret)
        if plaintext_secret is not None
        else _format_masked(ep)
    )
    return JSONResponse(status_code=201, content=content)


@router.get("")
async def list_webhooks(
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """List every webhook endpoint on the caller's tenant, disabled
    or not. Secrets are always masked in this response."""
    tenant_id = uuid.UUID(request.state.tenant_id)
    repo      = WebhookEndpointRepository(db)
    endpoints = await repo.list_by_tenant(tenant_id)
    return JSONResponse(content={
        "endpoints": [_format_masked(ep) for ep in endpoints],
    })


@router.get("/connector-types")
async def list_connector_types(
    principal: Principal = Depends(require_admin()),
):
    """Form schema per webhook destination type, for the dashboard's dynamic
    create form. Static metadata only -- no tenant data, no secrets. Declared
    before GET /{endpoint_id} so the literal path is not parsed as an id."""
    return JSONResponse(content={"connector_types": connector_forms()})


@router.get("/{endpoint_id}")
async def get_webhook(
    endpoint_id: uuid.UUID,
    request:     Request,
    db:          AsyncSession = Depends(get_db),
    principal:   Principal    = Depends(require_admin()),
):
    """Fetch one endpoint. Cross-tenant access returns 404 to prevent
    id enumeration."""
    tenant_id = uuid.UUID(request.state.tenant_id)
    repo      = WebhookEndpointRepository(db)
    ep        = await _get_owned_endpoint_or_404(repo, endpoint_id, tenant_id)
    return JSONResponse(content=_format_masked(ep))


@router.put("/{endpoint_id}")
async def update_webhook(
    endpoint_id: uuid.UUID,
    body:        WebhookUpdateSchema,
    request:     Request,
    db:          AsyncSession = Depends(get_db),
    principal:   Principal    = Depends(require_admin()),
):
    """Update mutable fields (url, description, event_types). Secret
    material, disabled flag, and circuit-breaker timer each have
    dedicated endpoints -- they cannot be changed here."""
    tenant_id = uuid.UUID(request.state.tenant_id)
    repo      = WebhookEndpointRepository(db)
    await _get_owned_endpoint_or_404(repo, endpoint_id, tenant_id)

    if body.url is not None:
        await _reject_bad_egress(body.url)

    # exclude_unset so an explicitly-set null clears the field (L2: description /
    # event_types / config were previously un-clearable because the old filter
    # dropped every None). url is required for a live endpoint and is never
    # cleared -- an explicit null for it is ignored.
    data = body.model_dump(exclude_unset=True)
    if data.get("url") is None:
        data.pop("url", None)
    ep   = await repo.update(endpoint_id=endpoint_id, data=data)
    if ep is None:
        raise NotFoundError("webhook_endpoint", str(endpoint_id))
    await db.commit()

    await _log_admin_event(
        db, request, principal, tenant_id,
        AdminEventAction.WEBHOOK_ENDPOINT_UPDATED,
        {
            "endpoint_id":    str(endpoint_id),
            "fields_changed": sorted(data.keys()),
        },
    )
    return JSONResponse(content=_format_masked(ep))


@router.delete("/{endpoint_id}")
async def delete_webhook(
    endpoint_id: uuid.UUID,
    request:     Request,
    db:          AsyncSession = Depends(get_db),
    principal:   Principal    = Depends(require_admin()),
):
    """Hard-delete an endpoint. Cross-tenant access returns 404."""
    tenant_id = uuid.UUID(request.state.tenant_id)
    repo      = WebhookEndpointRepository(db)
    await _get_owned_endpoint_or_404(repo, endpoint_id, tenant_id)

    await repo.delete(endpoint_id)
    await db.commit()

    await _log_admin_event(
        db, request, principal, tenant_id,
        AdminEventAction.WEBHOOK_ENDPOINT_DELETED,
        {"endpoint_id": str(endpoint_id)},
    )
    return JSONResponse(content={"endpoint_id": str(endpoint_id), "deleted": True})


@router.post("/{endpoint_id}/rotate-secret")
async def rotate_webhook_secret(
    endpoint_id: uuid.UUID,
    body:        WebhookRotateSchema,
    request:     Request,
    db:          AsyncSession = Depends(get_db),
    principal:   Principal    = Depends(require_admin()),
):
    """
    Rotate the signing secret. The current secret is moved into
    `old_secrets` with an `expires_at = now + grace_hours` and stays
    valid for signature verification during that window, giving the
    receiver time to update its verifier config. A fresh plaintext
    secret is returned in this response and nowhere else.
    """
    tenant_id = uuid.UUID(request.state.tenant_id)
    repo      = WebhookEndpointRepository(db)
    existing  = await _get_owned_endpoint_or_404(repo, endpoint_id, tenant_id)

    # Grace-window rotation is HMAC-signing specific: it keeps the old secret
    # valid for receiver-side signature verification. A connector's secret is
    # an ingest token the SIEM validates directly, so rotation-with-grace does
    # not apply -- delete and recreate the connector endpoint to change it.
    if existing.connector_type is not None:
        raise ValidationError(
            "secret rotation applies only to generic signed webhooks, not "
            f"connector endpoints ({existing.connector_type})"
        )

    plaintext_secret = pysecrets.token_urlsafe(_SECRET_BYTES)
    secret_enc       = encrypt(plaintext_secret, get_settings().secret_key)

    ep = await repo.rotate_secret(
        endpoint_id    = endpoint_id,
        new_secret_enc = secret_enc,
        grace_hours    = body.grace_hours,
    )
    if ep is None:
        raise NotFoundError("webhook_endpoint", str(endpoint_id))
    await db.commit()

    await _log_admin_event(
        db, request, principal, tenant_id,
        AdminEventAction.WEBHOOK_SECRET_ROTATED,
        {
            "endpoint_id": str(endpoint_id),
            "grace_hours": body.grace_hours,
        },
    )
    return JSONResponse(content=_format_with_plaintext(ep, plaintext_secret))


@router.post("/{endpoint_id}/pause")
async def pause_webhook(
    endpoint_id: uuid.UUID,
    request:     Request,
    db:          AsyncSession = Depends(get_db),
    principal:   Principal    = Depends(require_admin()),
):
    """Manually pause delivery to an endpoint. Stops events being forwarded
    while keeping the config, secret, and history intact -- resume with
    /reactivate. Idempotent on an already-paused endpoint."""
    tenant_id = uuid.UUID(request.state.tenant_id)
    repo      = WebhookEndpointRepository(db)
    await _get_owned_endpoint_or_404(repo, endpoint_id, tenant_id)

    ep = await repo.pause(endpoint_id=endpoint_id)
    if ep is None:
        raise NotFoundError("webhook_endpoint", str(endpoint_id))
    await db.commit()

    await _log_admin_event(
        db, request, principal, tenant_id,
        AdminEventAction.WEBHOOK_ENDPOINT_PAUSED,
        {"endpoint_id": str(endpoint_id)},
    )
    return JSONResponse(content=_format_masked(ep))


@router.post("/{endpoint_id}/reactivate")
async def reactivate_webhook(
    endpoint_id: uuid.UUID,
    request:     Request,
    db:          AsyncSession = Depends(get_db),
    principal:   Principal    = Depends(require_admin()),
):
    """Manually clear the circuit breaker (disabled + first_failure_at).
    Called after the admin has fixed the receiver and wants deliveries
    to resume. Idempotent on already-active endpoints."""
    tenant_id = uuid.UUID(request.state.tenant_id)
    repo      = WebhookEndpointRepository(db)
    await _get_owned_endpoint_or_404(repo, endpoint_id, tenant_id)

    ep = await repo.reactivate(endpoint_id=endpoint_id)
    if ep is None:
        raise NotFoundError("webhook_endpoint", str(endpoint_id))
    await db.commit()

    await _log_admin_event(
        db, request, principal, tenant_id,
        AdminEventAction.WEBHOOK_ENDPOINT_REACTIVATED,
        {"endpoint_id": str(endpoint_id)},
    )
    return JSONResponse(content=_format_masked(ep))


def _build_test_event() -> tuple[str, str, dict]:
    """A synthetic BLOCK event, clearly marked so a receiver/SIEM can filter
    it out. Carries no real tenant data -- placeholder values only."""
    msg_id = f"test-{uuid.uuid4()}"
    body = {
        "trace_id":       msg_id,
        "timestamp":      to_iso_z(utc_now()),
        "decision":       "BLOCK",
        "primary_reason": "RULE_DETECTOR",
        "risk_score":     0.99,
        "confidence":     1.0,
        "severity":       "HIGH",
        "source":         "webhook_test",
        "test":           True,
    }
    return msg_id, "wrapsec.request.blocked", body


@router.post("/{endpoint_id}/test")
async def test_webhook(
    endpoint_id: uuid.UUID,
    request:     Request,
    db:          AsyncSession = Depends(get_db),
    principal:   Principal    = Depends(require_admin()),
):
    """
    Send a synthetic test event to the endpoint and return the receiver's
    response. Synchronous and side-effect-free: it does NOT enqueue, write a
    delivery-attempt row, or move the circuit-breaker timer, so a test never
    pollutes delivery health.

    Security: ADMIN-only and tenant-scoped (cross-tenant returns 404, no
    enumeration). The destination is the endpoint's already-SSRF-validated
    stored URL -- the same target the delivery worker uses, no new egress
    surface. The response exposes only the receiver's status/body/timing; the
    endpoint secret and the outbound auth headers are never returned.
    """
    tenant_id = uuid.UUID(request.state.tenant_id)
    repo      = WebhookEndpointRepository(db)
    ep        = await _get_owned_endpoint_or_404(repo, endpoint_id, tenant_id)

    settings = get_settings()
    msg_id, event_type, body = _build_test_event()

    handler = WebhookDeliveryHandler(
        session_factory    = None,               # send_once touches no DB
        redis              = get_redis(),        # connector token cache only
        timeout_s          = settings.webhook_delivery_timeout_seconds,
        max_response_bytes = settings.webhook_delivery_max_response_bytes,
    )
    try:
        result = await handler.send_once(ep, event_type, body, msg_id)
    finally:
        await handler.aclose()

    await _log_admin_event(
        db, request, principal, tenant_id,
        AdminEventAction.WEBHOOK_ENDPOINT_TESTED,
        {"endpoint_id": str(endpoint_id), "ok": result.ok, "status_code": result.status_code},
    )

    # Only the receiver-facing outcome -- never the secret or request headers.
    return JSONResponse(content={
        "ok":               result.ok,
        "status_code":      result.status_code,
        "response_snippet": result.response_snippet,
        "duration_ms":      result.duration_ms,
        "error":            result.error,
    })
