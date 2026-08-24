# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
import hmac
import ipaddress
import logging
import os
from typing import TYPE_CHECKING, cast
from uuid import UUID

from fastapi import Request
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from starlette.background import BackgroundTask
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from cache import keyspace
from config.settings import get_settings
from errors.catalog import ErrorCode
from errors.response import error_response
from observability.metrics import record_api_key_ip_denied
from security.ip_allowlist import is_allowed
from services.time import utc_now

if TYPE_CHECKING:
    from db.models import UserModel

logger = logging.getLogger("wrapsec.auth")

_auth_event_engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
_auth_event_sf     = async_sessionmaker(bind=_auth_event_engine, class_=AsyncSession,
                                        expire_on_commit=False)

PUBLIC_PATHS = {
    "/health",
    "/health/ready",
    "/health/live",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/v1/auth/login",    # login is public - no auth required
    "/v1/auth/refresh",  # refresh uses httpOnly cookie - no Bearer required
    "/v1/setup",         # first-run setup - public, self-disables after first user created
    "/v1/setup/status",  # initialization check - public
}

# Paths where middleware must NOT log SESSION_EXPIRED
# (refresh service owns its own logging for these paths)
SKIP_AUTH_EVENT_LOGGING = {"/v1/auth/refresh"}

# Paths accessible even when force_password_change = True
FORCE_CHANGE_ALLOWED = {
    "/v1/auth/change-password",
    "/v1/auth/logout",
    "/v1/auth/me",
}

_TESTING = os.getenv("TESTING") == "true"


def _parse_trusted_proxy_nets(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            logger.warning("trusted_proxy_ips: ignoring invalid entry %r", entry)
            continue

        # A zero-prefix network matches every address, so trusting it means
        # believing a forwarded header from any peer -- the spoofing this list
        # exists to prevent. `0.0.0.0/0` parses cleanly and reads like
        # configuration, so the control would look enabled while doing nothing.
        # Ignored rather than fatal: dropping the entry falls back to the direct
        # peer, which is the safe direction, and an unusable value must not stop
        # the gateway booting. ip_allowlist.normalize_entries applies the same
        # rule but raises, because it runs at configuration time.
        if net.prefixlen == 0:
            logger.warning(
                "trusted_proxy_ips: ignoring %r -- it matches every address. "
                "Leave the setting empty to use the direct connection address.",
                entry,
            )
            continue

        nets.append(net)
    return nets


def get_client_ip(request: Request) -> str:
    """
    Returns the real client IP, trusting x-forwarded-for only when the
    direct connection IP is listed in TRUSTED_PROXY_IPS. Without a trusted
    proxy guard, any client can set x-forwarded-for to spoof their IP in
    audit logs and bypass IP-based controls.

    A reverse proxy APPENDS the real peer IP to whatever the client sent, so the
    trustworthy value is the RIGHTMOST entry (added by our proxy), not the
    leftmost (client-controlled). We walk the chain right-to-left, skipping
    further trusted-proxy hops, and return the first non-trusted address. Taking
    [0] would let a client set `X-Forwarded-For: 1.2.3.4` and spoof its recorded
    IP even behind a correctly-configured trusted proxy.
    """
    direct_ip = (request.client.host if request.client else None) or "unknown"
    chain     = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]

    if not chain:
        return direct_ip

    trusted_raw = get_settings().trusted_proxy_ips
    if not trusted_raw:
        return direct_ip

    try:
        addr = ipaddress.ip_address(direct_ip)
    except ValueError:
        return direct_ip

    nets = _parse_trusted_proxy_nets(trusted_raw)
    if not any(addr in net for net in nets):
        # Direct peer is not a trusted proxy: the header is unverified, ignore it.
        return direct_ip

    def _is_trusted(ip_str: str) -> bool:
        try:
            return any(ipaddress.ip_address(ip_str) in net for net in nets)
        except ValueError:
            return False

    for candidate in reversed(chain):
        if _is_trusted(candidate):
            continue  # another trusted-proxy hop -- keep walking left
        try:
            ipaddress.ip_address(candidate)   # only trust a well-formed address
        except ValueError:
            return direct_ip
        return candidate

    # Entire chain is trusted proxies -- fall back to the direct peer.
    return direct_ip


def _unauthorized(request: Request, reason: str) -> JSONResponse:
    """
    Returns 401 JSONResponse. Always logs reason and path.
    Every auth rejection is visible in logs - no silent 401s.
    """
    logger.warning(
        "auth rejected reason=%s path=%s method=%s",
        reason, request.url.path, request.method,
    )
    return error_response(
        ErrorCode.UNAUTHORIZED,
        trace_id=getattr(request.state, "trace_id", "") or "",
    )


# The one route whose callers are OpenAI clients. A refusal there has to be
# shaped like an OpenAI error or the client library raises on the body instead
# of surfacing the status, and the caller never learns why they were refused.
_OPENAI_COMPATIBLE_PATHS = frozenset({"/v1/chat/completions"})


def bare_key_id(state_key_id: str | None) -> str | None:
    """
    The credential id as stored on the key, from the prefixed form request state
    carries. State distinguishes credential kinds ("key:wsk_...", "key:admin",
    "user:<uuid>"); the stored id has no prefix, and only a machine credential
    has one to record.
    """
    if not state_key_id or not state_key_id.startswith("key:"):
        return None
    bare = state_key_id[len("key:"):]
    return bare or None


async def _record_ip_denial(request: Request) -> None:
    """
    Record a credential refused for the address it was presented from.

    Goes to the credential event log rather than the request trail: nothing was
    scanned and no decision was made, so a row in the decision trail would need
    an invented decision, and those numbers feed block-rate and threat
    analytics.

    Written on its own session, and best-effort. A refusal that cannot be
    recorded is still a refusal, so this swallows its own failures rather than
    turning an audit problem into a request failure. The credential is named so
    revoking one key does not mean auditing all of them.

    Runs as a background task on the denial response, so the caller is answered
    before this is attempted. Anything raised here would surface after the
    response has been sent, which is why nothing is allowed to.
    """
    from domain.enums import AuthEventAction, AuthFailureReason
    from services.auth.service import _log_auth_event

    tenant_id = getattr(request.state, "tenant_id", None)
    try:
        await _log_auth_event(
            action         = AuthEventAction.API_KEY_IP_DENIED.value,
            success        = False,
            tenant_id      = UUID(tenant_id) if tenant_id else None,
            user_id        = None,
            failure_reason = AuthFailureReason.IP_NOT_ALLOWED.value,
            ip_address     = getattr(request.state, "ip_address", None),
            user_agent     = (getattr(request.state, "user_agent", None) or "")[:500] or None,
            key_id         = bare_key_id(getattr(request.state, "key_id", None)),
        )
    except Exception as exc:
        logger.error("Could not record a source-network denial: %s", exc)


def _ip_denied_response(request: Request) -> Response:
    """
    Refuse the request in the shape its caller can read.

    The proxy is consumed by OpenAI client libraries, which parse the body
    before the status; everything else is consumed by callers that expect the
    standard envelope. One control, two renderings, because a refusal nobody
    can interpret is a support ticket rather than a security signal.

    The SHAPE varies by protocol; the CODE does not. Both carry
    `IP_NOT_ALLOWED`, because an alert keyed on the code has to catch this
    denial wherever the credential was presented -- and a rule written against
    the proxy's code that silently misses the same denial on the scan endpoints
    would teach its author that the restriction only applies to the proxy,
    which is the misunderstanding this control was moved to remove.

    It is also distinct from the generic permission failure. Being refused for
    where you are is a different event from being refused for who you are, and
    only a distinct code lets an alert tell them apart.

    The message says the credential is not permitted from this address without
    naming what is permitted. Whoever is holding the key is not necessarily
    whoever is allowed to know the network layout.
    """
    trace_id = getattr(request.state, "trace_id", "") or ""
    message  = "This credential is not permitted from your network address."

    if request.url.path in _OPENAI_COMPATIBLE_PATHS:
        return JSONResponse(
            status_code = 403,
            content     = {
                "error": {
                    "message": message,
                    "type":    "forbidden",
                    "code":    ErrorCode.IP_NOT_ALLOWED.value,
                },
                "wrapsec": {"trace_id": trace_id},
            },
            headers     = {"X-WrapSec-Trace-Id": trace_id},
        )

    return error_response(
        ErrorCode.IP_NOT_ALLOWED,
        trace_id = trace_id,
        message  = message,
    )


async def _log_session_expired(
    token:          str,
    failure_reason: str,
    path:           str,
) -> None:
    """
    Logs SESSION_EXPIRED to auth_events.

    Attempts to extract user_id and tenant_id from the token payload
    even if the token is expired or invalid (decode without expiry check).
    If extraction fails, logs with NULL context - never skips logging.

    Non-blocking: NullPool session, best-effort, always closes in finally.
    Must NOT be called when no token is present (noise from health checks).
    Must NOT be called for /v1/auth/refresh path (service owns that logging).
    """
    from uuid import UUID as _UUID

    user_id   = None
    tenant_id = None

    # Attempt context extraction from token even if invalid/expired
    try:
        import jwt as _jwt

        from config.settings import get_settings as _get_settings
        _s = _get_settings()
        raw_payload = _jwt.decode(
            token,
            _s.secret_key,
            algorithms = [_s.jwt_algorithm],
            options    = {"verify_exp": False, "verify_aud": False},
        )
        sub = raw_payload.get("sub")
        tid = raw_payload.get("tenant_id")
        if sub:
            try:
                user_id = _UUID(sub)
            except (ValueError, TypeError):
                pass
        if tid:
            try:
                tenant_id = _UUID(tid)
            except (ValueError, TypeError):
                pass
    except Exception as e:
        logger.debug("auth session_expired context extraction failed: %s", e)

    logger.warning(
        "auth_event SESSION_EXPIRED user_id=%s tenant_id=%s reason=%s path=%s",
        user_id, tenant_id, failure_reason, path,
    )

    from db.repositories.auth_event import AuthEventRepository
    from domain.enums import AuthEventAction as _Action
    from domain.enums import AuthFailureReason as _Reason

    session = _auth_event_sf()
    try:
        repo = AuthEventRepository(session)
        await repo.insert(
            action         = _Action.SESSION_EXPIRED,
            success        = False,
            tenant_id      = tenant_id,
            user_id        = user_id,
            failure_reason = _Reason(failure_reason),
        )
        await session.commit()
    except Exception as e:
        logger.error("auth_event DB logging failed action=session_expired error=%s", e)
    finally:
        await session.close()


_USER_CACHE_TTL = 1800  # seconds - matches JWT access token expiry
_USER_DB_ERROR  = object()  # sentinel: DB/Redis failure, distinct from "user not found"


async def _get_user_cached(user_uuid: UUID, user_id_str: str):
    """
    Returns the user record for JWT auth, using Redis as a read-through cache.
    Cache key: auth:user:{user_id}, TTL: 1800s (JWT expiry).
    Cache is invalidated in logout_all_sessions() whenever token_version changes.

    Return values:
      SimpleNamespace / ORM user - found (cache hit or DB hit)
      None                       - user does not exist in DB
      _USER_DB_ERROR             - DB/Redis failure (caller returns 500-equivalent)
    """
    import json
    from types import SimpleNamespace

    cache_key = keyspace.auth_user(user_id_str)

    # Cache read
    if not _TESTING:
        try:
            from cache.redis_client import get_redis
            raw = await get_redis().get(cache_key)
            if raw:
                d = json.loads(raw)
                return SimpleNamespace(**d)
        except Exception as e:
            logger.debug("auth user cache read failed user_id=%s error=%s", user_id_str, e)

    # Cache miss or test mode - DB lookup. Loads identity plus the user's
    # memberships (the authz source under D2 Option B): a map keyed by tenant_id.
    from db.repositories.membership import MembershipRepository
    from db.repositories.user import UserRepository
    try:
        engine, session_ctx = await _get_db_session()
        async with session_ctx as session:
            user = await UserRepository(session).get_by_id(user_uuid)
            memberships: dict = {}
            if user is not None:
                mems = await MembershipRepository(session).list_for_user(user.id)
                memberships = {
                    str(m.tenant_id): {
                        "role":    m.role,
                        "dept_id": str(m.dept_id) if m.dept_id else None,
                    }
                    for m in mems
                }
        if engine:
            await engine.dispose()
    except Exception as e:
        logger.error("auth JWT db_lookup_failed user_id=%s error=%s", user_id_str, e)
        return _USER_DB_ERROR

    if user is None:
        return None

    payload = {
        "id":                    str(user.id),
        "is_active":             user.is_active,
        "force_password_change": user.force_password_change,
        "token_version":         user.token_version,
        "email":                 user.email,
        "memberships":           memberships,
    }

    # Write to cache (production only - skip in tests)
    if not _TESTING:
        try:
            from cache.redis_client import get_redis
            await get_redis().set(cache_key, json.dumps(payload), ex=_USER_CACHE_TTL)
        except Exception as e:
            logger.debug("auth user cache write failed user_id=%s error=%s", user_id_str, e)

    return SimpleNamespace(**payload)


async def _get_db_session():
    """
    Returns an async session appropriate for the current environment.

    Production: uses AsyncSessionFactory (pooled, efficient)
    Testing: uses NullPool engine (no cross-loop pool poisoning)

    NullPool opens/closes a fresh connection each time - slightly slower
    but completely safe when each pytest test function gets its own event loop.
    """
    if _TESTING:
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )
        from sqlalchemy.pool import NullPool
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        sf     = async_sessionmaker(bind=engine, class_=AsyncSession,
                                     expire_on_commit=False)
        return engine, sf()
    else:
        from db.session import AsyncSessionFactory
        return None, AsyncSessionFactory()


async def _tenant_suspended(tenant_id: str | None) -> bool:
    """
    True when the tenant may not be served: suspended, or in a state that could
    not be established. Read-through cache (auth:tenant:{id}, short TTL) then DB.

    FAILS CLOSED. A lookup error returns True, so a credential is refused while
    the tenant's status is unknown rather than served on the assumption that it
    is active. The documented contract is that a suspended tenant's credentials
    return 403 on every request; returning False here made that true only while
    the datastore was reachable, and a suspended tenant regained access during
    exactly the disturbance nobody is watching.

    The cost is explicit: a datastore outage refuses authenticated traffic
    rather than degrading enforcement. That is the same trade the detection path
    already makes, and the opposite of the rate limiter, which fails open
    because exceeding a quota is not a security boundary. Suspension is.

    An unknown tenant is NOT suspended: the row simply not existing is a
    definite answer, and other guards handle an unrecognised tenant. Only an
    unanswerable lookup fails closed.
    """
    if not tenant_id:
        return False

    if not _TESTING:
        try:
            from cache.redis_client import get_redis
            cached = await get_redis().get(keyspace.auth_tenant(tenant_id))
            if cached is not None:
                status = cached.decode() if isinstance(cached, bytes) else cached
                return status != "active"
        except Exception as e:
            logger.debug("tenant status cache read failed tenant=%s error=%s", tenant_id, e)

    try:
        from db.repositories.tenant import TenantRepository
        engine, session_ctx = await _get_db_session()
        async with session_ctx as session:
            tenant = await TenantRepository(session).get_by_id(UUID(str(tenant_id)))
        if engine:
            await engine.dispose()
        # Unknown tenant is not blocked here (other guards handle it); only an
        # explicit non-active status suspends.
        status = tenant.status if tenant else "active"
        if not _TESTING:
            try:
                from cache.redis_client import get_redis
                await get_redis().set(keyspace.auth_tenant(tenant_id), status, ex=60)
            except Exception:
                pass  # best-effort cache write
        return status != "active"
    except Exception as e:
        logger.error(
            "tenant status lookup failed, refusing the request tenant=%s error=%s",
            tenant_id, e,
        )
        return True


def _tenant_suspended_response(request: Request) -> Response:
    return error_response(
        ErrorCode.TENANT_SUSPENDED,
        trace_id=getattr(request.state, "trace_id", "") or "",
        message="This tenant is suspended. Contact your platform operator.",
    )


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Dual-identity auth middleware - API key and JWT coexist.

    Header precedence (absolute, no exceptions):
        IF x-api-key present (non-empty after strip) -> API key path
        ELIF Authorization: Bearer ... -> JWT path
        ELSE -> 401

    API key always wins - JWT is ignored even if valid when x-api-key is present.
    All paths set identical request.state fields - downstream code is auth-agnostic.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in PUBLIC_PATHS:
            request.state.is_admin = False
            return await call_next(request)

        # Always capture network attribution
        request.state.ip_address = get_client_ip(request)
        request.state.user_agent = request.headers.get("user-agent", "")

        # Initialise all state fields
        request.state.key_id         = None
        request.state.ip_allowlist   = None
        request.state.key_name       = None
        request.state.key_type       = "live"
        request.state.app_id         = None
        request.state.dept_id        = None
        request.state.tenant_id      = None
        request.state.is_admin       = False
        request.state.principal_type = "api_key"
        request.state.user_id        = None
        request.state.user_role      = None

        # ── Header precedence - absolute rule ─────────────────────────────────
        api_key = request.headers.get("x-api-key", "").strip()
        auth    = request.headers.get("authorization", "").strip()

        if api_key:
            return await self._authenticate_api_key(api_key, request, call_next)
        elif auth.lower().startswith("bearer "):
            return await self._authenticate_jwt(auth[7:], request, call_next)
        else:
            return _unauthorized(request, "missing_credentials")

    # ── API key path ───────────────────────────────────────────────────────────

    async def _authenticate_api_key(
        self, api_key: str, request: Request, call_next
    ) -> Response:
        if hmac.compare_digest(api_key, get_settings().admin_api_key or ""):
            return await self._authenticate_admin_key(request, call_next)

        if api_key.startswith(("wsk_live_", "wsk_trial_")):
            key_record = await self._get_standard_key(api_key)
            if key_record:
                request.state.principal_type = "api_key"
                request.state.key_id         = f"key:{key_record.key_id}"
                request.state.key_name       = key_record.name
                request.state.key_type       = getattr(key_record, "key_type", "live") or "live"
                request.state.is_admin       = False
                request.state.app_id         = str(key_record.app_id)    if key_record.app_id    else None
                request.state.dept_id        = str(key_record.dept_id)   if key_record.dept_id   else None
                request.state.tenant_id      = str(key_record.tenant_id) if key_record.tenant_id else None
                request.state.user_id        = None
                request.state.user_role      = None
                # Source networks this credential is restricted to. Null or
                # empty means unrestricted; the feature is off for that key.
                request.state.ip_allowlist   = getattr(key_record, "ip_allowlist", None)

                # Enforced here rather than in an endpoint, because the
                # restriction belongs to the credential and not to a route. In
                # a handler it would only ever cover the handlers that
                # remembered to check, and a credential confined to one network
                # would still be accepted everywhere else. Here it covers every
                # request that presents an API key, including routes added
                # later, and a denied request reaches no handler at all: no
                # policy resolution, no detection, no upstream call.
                #
                # Ahead of the suspension check because it is the cheaper
                # refusal -- no cache or database round trip for a request that
                # is not going to be served.
                #
                # The address comes from get_client_ip, which believes a
                # forwarded header only when the immediate peer is a configured
                # trusted proxy, so a caller cannot present an approved address
                # by claiming one.
                if request.state.ip_allowlist and not is_allowed(
                    request.state.ip_address, request.state.ip_allowlist
                ):
                    logger.warning(
                        "auth rejected reason=ip_not_allowed path=%s key=%s ip=%s",
                        request.url.path,
                        request.state.key_id,
                        request.state.ip_address,
                    )
                    record_api_key_ip_denied()

                    # Recorded AFTER the response is sent, not before it.
                    #
                    # This is the path a misconfigured client hammers in a
                    # retry loop, and the code above describes it as the cheap
                    # refusal -- so paying for a database insert before
                    # answering made the denial more expensive than the allow,
                    # and amplified load under exactly the condition it exists
                    # to shed. The recorder's own contract says the write must
                    # never delay the request it describes; awaiting it here
                    # said otherwise.
                    #
                    # A background task on the response, rather than a bare
                    # task: a detached task can be garbage collected mid-flight
                    # and takes its exceptions with it, whereas this one is
                    # owned by the response and runs to completion.
                    response = _ip_denied_response(request)
                    response.background = BackgroundTask(_record_ip_denial, request)
                    return response

                if await _tenant_suspended(request.state.tenant_id):
                    return _tenant_suspended_response(request)
                return await call_next(request)
            else:
                return _unauthorized(request, "invalid_api_key")

        return _unauthorized(request, "unrecognized_key_format")

    async def _authenticate_admin_key(
        self, request: Request, call_next
    ) -> Response:
        """
        Handles the hardcoded admin key.
        Production: fetches real tenant_id from DB.
        Test mode: skips DB fetch -> tenant_id = None (matches original behaviour).
        """
        tenant_id = None

        if not _TESTING:
            try:
                from db.repositories.tenant import TenantRepository
                from db.session import AsyncSessionFactory
                async with AsyncSessionFactory() as session:
                    tenant = await TenantRepository(session).get_bootstrap_default()
                if tenant:
                    tenant_id = str(tenant.id)
                else:
                    logger.error("auth admin_key no_default_tenant path=%s",
                                 request.url.path)
                    return _unauthorized(request, "system_configuration_error")
            except Exception as e:
                logger.error("auth admin_key tenant_fetch_failed path=%s error=%s",
                             request.url.path, e)
                return _unauthorized(request, "system_configuration_error")

        request.state.principal_type = "api_key"
        request.state.key_id         = "key:admin"
        # Deliberately unrestricted, and deliberately not a gap left open.
        #
        # A source-network list lives on an `api_keys` row. This credential has
        # no row -- it is matched against a configured secret -- so there is
        # nothing to attach one to and nothing to enforce. The exemption is a
        # consequence of what it is, not a decision to exempt it.
        #
        # It is also the most privileged credential in the system, so the
        # consequence is worth stating rather than leaving to be discovered:
        # this one cannot be confined to a network by the application, and has
        # to be confined by the network itself -- a firewall or reverse proxy
        # in front of the API.
        request.state.ip_allowlist   = None
        request.state.key_name       = "Admin Key"
        request.state.key_type       = "live"
        request.state.is_admin       = True
        request.state.dept_id        = None
        request.state.tenant_id      = tenant_id
        request.state.app_id         = None
        request.state.user_id        = None
        request.state.user_role      = None

        return await call_next(request)

    # ── JWT path ───────────────────────────────────────────────────────────────

    async def _authenticate_jwt(
        self, token: str, request: Request, call_next
    ) -> Response:
        """
        JWT authentication path.
        Uses NullPool session in test mode to avoid asyncpg pool poisoning.
        Uses AsyncSessionFactory in production for efficiency.
        """
        from services.auth.token import decode_access_token

        # Step 1 - decode and validate JWT
        # ExpiredSignatureError must be caught BEFORE InvalidTokenError
        # (it is a subclass - order is mandatory, never swap)
        skip_logging = request.url.path in SKIP_AUTH_EVENT_LOGGING
        try:
            payload = decode_access_token(token)
        except ExpiredSignatureError:
            if not skip_logging:
                await _log_session_expired(token, "token_expired", request.url.path)
            return _unauthorized(request, "invalid_or_expired_token")
        except InvalidTokenError:
            if not skip_logging:
                await _log_session_expired(token, "token_invalid", request.url.path)
            return _unauthorized(request, "invalid_or_expired_token")

        # M1: reject tokens whose jti was blacklisted by /logout. Runs before
        # any DB lookup so a revoked token cannot even probe user state.
        from services.auth.jti_blacklist import is_blacklisted
        if await is_blacklisted(payload["jti"]):
            if not skip_logging:
                await _log_session_expired(token, "token_revoked", request.url.path)
            return _unauthorized(request, "invalid_or_expired_token")

        # Step 2 - parse sub claim
        user_id_str = payload.get("sub") or ""
        try:
            user_uuid = UUID(user_id_str)
        except (ValueError, TypeError):
            logger.warning("auth JWT invalid_sub_format user_id=%s path=%s",
                           user_id_str, request.url.path)
            return _unauthorized(request, "invalid_token")

        # Step 2a - load user (Redis cache -> DB fallback)
        user = await _get_user_cached(user_uuid, user_id_str)
        if user is _USER_DB_ERROR:
            return _unauthorized(request, "internal_error")

        # Step 2b - existence
        if not user:
            logger.warning("auth JWT user_not_found user_id=%s path=%s",
                           user_id_str, request.url.path)
            return _unauthorized(request, "invalid_token")

        # After the sentinel/existence guards above, user is a UserModel.
        user = cast("UserModel", user)

        # Step 2c - active
        if not user.is_active:
            logger.warning("auth JWT user_disabled user_id=%s path=%s",
                           user_id_str, request.url.path)
            return _unauthorized(request, "account_disabled")

        # Step 3 - resolve the membership the token is scoped to (D2 Option B).
        # The user must hold a membership in the token's tenant; role/dept are
        # sourced from it, so a token can never carry authz the DB no longer
        # grants. A token whose tenant the user is not a member of is rejected -
        # this is the cross-tenant boundary that the old user.tenant_id check was.
        token_tenant = payload.get("tenant_id")
        memberships  = getattr(user, "memberships", None) or {}
        membership   = memberships.get(token_tenant)
        if membership is None:
            logger.error(
                "auth JWT no_membership_for_tenant user_id=%s token_tenant=%s path=%s",
                user_id_str, token_tenant, request.url.path,
            )
            return _unauthorized(request, "invalid_token")

        # Step 3b - dept_id mismatch log (warning only)
        token_dept = payload.get("dept_id")
        db_dept    = membership["dept_id"]
        if token_dept != db_dept:
            logger.warning(
                "auth_event JWT_DEPT_MISMATCH user_id=%s token_dept=%s db_dept=%s",
                user_id_str, token_dept, db_dept,
            )

        # Step 4 - token version check
        if payload.get("ver") != user.token_version:
            logger.warning(
                "auth_event SESSION_EXPIRED user_id=%s reason=session_invalidated "
                "token_ver=%s user_ver=%s path=%s",
                user_id_str, payload.get("ver"),
                user.token_version, request.url.path,
            )
            if not skip_logging:
                await _log_session_expired(token, "session_invalidated", request.url.path)
            return error_response(
                ErrorCode.SESSION_INVALIDATED,
                trace_id=getattr(request.state, "trace_id", "") or "",
            )

        # Step 5 - populate request.state: identity from the user, authz from the
        # resolved membership (role/dept/tenant).
        request.state.principal_type = "user"
        request.state.key_id         = f"user:{user.id}"
        request.state.key_name       = user.email
        request.state.key_type       = "live"
        request.state.is_admin       = (membership["role"] == "ADMIN")
        request.state.dept_id        = membership["dept_id"]
        request.state.tenant_id      = token_tenant
        request.state.app_id         = None
        request.state.user_id        = str(user.id)
        request.state.user_role      = membership["role"]

        # Step 5b - suspend enforcement: a suspended tenant's users are blocked.
        if await _tenant_suspended(token_tenant):
            return _tenant_suspended_response(request)

        # Step 6 - force_password_change enforcement
        if user.force_password_change and request.url.path not in FORCE_CHANGE_ALLOWED:
            return error_response(
                ErrorCode.PASSWORD_CHANGE_REQUIRED,
                trace_id=getattr(request.state, "trace_id", "") or "",
            )

        return await call_next(request)

    # ── Standard key DB validation (unchanged) ────────────────────────────────

    async def _get_standard_key(self, api_key: str):
        try:
            from db.repositories.api_key import ApiKeyRepository
            from db.session import AsyncSessionFactory

            key_hash = hashlib.sha256(api_key.encode()).hexdigest()

            async with AsyncSessionFactory() as session:
                repo   = ApiKeyRepository(session)
                record = await repo.get_by_hash(key_hash)

                if not record or record.revoked:
                    return None

                if record.expires_at is not None and utc_now() > record.expires_at:
                    return None

                try:
                    record.last_used_at = utc_now()
                    await session.commit()
                except Exception as e:
                    logger.warning("Failed to update last_used_at for %s: %s",
                                   record.key_id, e)

                return record

        except Exception as e:
            logger.error("Key validation failed: %s", e)
            return None
