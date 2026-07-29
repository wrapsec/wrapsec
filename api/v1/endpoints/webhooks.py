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
from pydantic import BaseModel, Field, field_validator
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
from errors.exceptions import NotFoundError
from security.encryption import encrypt, mask
from security.url_validator import validate_llm_base_url

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
    url:         str
    description: str        | None = None
    event_types: list[str]  | None = None

    @field_validator("url")
    @classmethod
    def _url_must_be_ssrf_safe(cls, v: str) -> str:
        # Reuses the shared SSRF validator (same one gating LLM
        # provider URLs). Blocks localhost/metadata/private-range
        # targets so a compromised admin cannot repurpose the
        # delivery worker as an egress SSRF primitive.
        return validate_llm_base_url(v)


class WebhookUpdateSchema(BaseModel):
    url:         str        | None = None
    description: str        | None = None
    event_types: list[str]  | None = None

    @field_validator("url")
    @classmethod
    def _url_must_be_ssrf_safe(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return validate_llm_base_url(v)


class WebhookRotateSchema(BaseModel):
    grace_hours: int = Field(_DEFAULT_ROTATION_GRACE_HOURS, ge=1, le=168)


# ─── Formatting helpers ─────────────────────────────────────────────

def _format_masked(ep: WebhookEndpointModel) -> dict:
    """Read-side projection. NEVER contains plaintext secret or the
    ciphertext of the current or old secrets -- only a mask derived
    from the ciphertext string so operators can spot rotations
    without exposing key material."""
    return {
        "id":                str(ep.id),
        "tenant_id":         str(ep.tenant_id),
        "url":               ep.url,
        "description":       ep.description,
        "event_types":       ep.event_types,
        "disabled":          ep.disabled,
        "first_failure_at":  ep.first_failure_at.isoformat() if ep.first_failure_at else None,
        "secret_masked":     mask(ep.secret_enc or ""),
        "created_at":        ep.created_at.isoformat() if ep.created_at else None,
        "updated_at":        ep.updated_at.isoformat() if ep.updated_at else None,
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
    except Exception as exc:                              # noqa: BLE001
        logger.warning("webhook admin_event log failed: %s", exc)


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

    plaintext_secret = pysecrets.token_urlsafe(_SECRET_BYTES)
    secret_enc       = encrypt(plaintext_secret, get_settings().secret_key)

    repo = WebhookEndpointRepository(db)
    ep   = await repo.create(
        tenant_id   = tenant_id,
        url         = body.url,
        secret_enc  = secret_enc,
        description = body.description,
        event_types = body.event_types,
    )
    await db.commit()

    await _log_admin_event(
        db, request, principal, tenant_id,
        AdminEventAction.WEBHOOK_ENDPOINT_CREATED,
        {
            "endpoint_id": str(ep.id),
            "url":         ep.url,
            "event_types": ep.event_types,
        },
    )

    return JSONResponse(
        status_code=201,
        content=_format_with_plaintext(ep, plaintext_secret),
    )


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

    data = {k: v for k, v in body.model_dump().items() if v is not None}
    ep   = await repo.update(endpoint_id=endpoint_id, data=data)
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
    await _get_owned_endpoint_or_404(repo, endpoint_id, tenant_id)

    plaintext_secret = pysecrets.token_urlsafe(_SECRET_BYTES)
    secret_enc       = encrypt(plaintext_secret, get_settings().secret_key)

    ep = await repo.rotate_secret(
        endpoint_id    = endpoint_id,
        new_secret_enc = secret_enc,
        grace_hours    = body.grace_hours,
    )
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
    await db.commit()

    await _log_admin_event(
        db, request, principal, tenant_id,
        AdminEventAction.WEBHOOK_ENDPOINT_REACTIVATED,
        {"endpoint_id": str(endpoint_id)},
    )
    return JSONResponse(content=_format_masked(ep))
