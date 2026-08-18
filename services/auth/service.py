# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cache import keyspace
from config.settings import get_settings as _get_settings
from services.time import ensure_utc, utc_now

if TYPE_CHECKING:
    from db.models import MembershipModel, UserModel

logger = logging.getLogger("wrapsec.auth")

# Dedicated NullPool engine for auth_event writes - kept at module level so the
# engine object is not re-created on every login attempt. NullPool still opens
# a fresh DB connection per session; dispose() is never needed at this scope.
_auth_settings    = _get_settings()
_auth_event_engine = create_async_engine(_auth_settings.database_url, poolclass=NullPool)
_auth_event_sf     = async_sessionmaker(bind=_auth_event_engine, class_=AsyncSession,
                                        expire_on_commit=False)


def _utcnow() -> datetime:
    return utc_now()


async def _resolve_active_membership(db: AsyncSession, user_id: UUID):
    """
    Returns the membership the session is scoped to, or None if the user holds
    none (callers fail closed -- no membership means no tenant/authz context).

    At N=1 a user has exactly one membership. Until the post-auth tenant switcher
    lands, the oldest membership is the deterministic default active one.
    """
    from db.repositories.membership import MembershipRepository

    memberships = await MembershipRepository(db).list_for_user(user_id)
    return memberships[0] if memberships else None


def _to_db(dt: datetime) -> datetime:
    # DB columns are TIMESTAMPTZ. Normalize to aware UTC so any naive value
    # still binds correctly as an instant rather than a session-TZ guess.
    return ensure_utc(dt)


async def _log_auth_event(
    action:         str,
    success:        bool,
    tenant_id:      UUID | None = None,
    user_id:        UUID | None = None,
    failure_reason: str  | None = None,
    ip_address:     str  | None = None,
    user_agent:     str  | None = None,
) -> None:
    """
    Inserts an auth_event row using a separate NullPool DB session.

    Non-blocking: independent session, never touches the request session.
    Best-effort: exceptions are logged and suppressed - never affect auth flow.
    Session is always closed in finally block - NullPool does not pool connections.

    tenant_id / user_id:
        Known user   -> set from user record
        Unknown user -> both None (user not found, cannot resolve tenant)
    """
    from db.repositories.auth_event import AuthEventRepository
    from domain.enums import AuthEventAction as _Action
    from domain.enums import AuthFailureReason as _Reason

    session = _auth_event_sf()
    try:
        repo = AuthEventRepository(session)
        await repo.insert(
            action         = _Action(action),
            success        = success,
            tenant_id      = tenant_id,
            user_id        = user_id,
            failure_reason = _Reason(failure_reason) if failure_reason else None,
            ip_address     = ip_address,
            user_agent     = user_agent,
        )
        await session.commit()
    except Exception as e:
        logger.error("auth_event DB logging failed action=%s error=%s", action, e)
    finally:
        await session.close()


@dataclass
class LoginResult:
    access_token:          str
    refresh_token:         str
    expires_in:            int
    force_password_change: bool
    user:                  "UserModel"
    membership:            "MembershipModel"


@dataclass
class RefreshResult:
    access_token:  str
    refresh_token: str
    expires_in:    int
    user:          "UserModel"
    membership:    "MembershipModel"


class AuthService:

    async def login(
        self,
        email:      str,
        password:   str,
        db:         AsyncSession,
        ip_address: str | None = None,
        user_agent: str | None = None,
        method:     str        = "password",
    ) -> LoginResult:
        """
        Full login flow.

        ip_address and user_agent are optional - passed from the request for
        auth_events logging. Login succeeds regardless of their presence.

        method selects the identity backend from the AuthProvider registry
        (default "password"). SSO/OIDC/SAML plugins register additional methods;
        a future SSO endpoint passes method=<name>. An unknown method is treated
        as an authentication failure (it never leaks which methods exist).

        auth_events logging is non-blocking: uses _log_auth_event() which
        opens a separate NullPool session. Failures are swallowed.
        The existing wrapsec.auth logger is preserved for real-time monitoring.
        """
        from config.settings import get_settings
        from db.repositories.refresh_token import RefreshTokenRepository
        from db.repositories.user import UserRepository
        from errors.exceptions import (
            AccountDisabledException,
            AccountLockedException,
            AuthenticationError,
        )
        from services.auth.lockout import (
            clear_failures,
            get_lockout_remaining,
            is_locked,
            record_failure,
        )
        from services.auth.password import normalize_email
        from services.auth.providers.registry import get_auth_provider
        from services.auth.token import create_access_token, create_refresh_token

        _settings = get_settings()
        email     = normalize_email(email)

        # Lockout state lives in Redis. Fail OPEN on any Redis error -- exactly
        # like the login IP rate limit, jti blacklist, and user cache in this same
        # flow -- so a Redis outage degrades brute-force protection but never turns
        # a valid login into a 500 (M1).
        async def _safe_is_locked() -> int | None:
            try:
                if await is_locked(email):
                    return await get_lockout_remaining(email)
            except Exception as exc:  # fail open on any lockout-store error
                logger.warning("lockout check failed open (redis unavailable?): %s", exc)
            return None

        async def _safe_record_failure() -> tuple[int, bool]:
            try:
                return await record_failure(email)
            except Exception as exc:  # fail open on any lockout-store error
                logger.warning("lockout record failed open (redis unavailable?): %s", exc)
                return 0, False

        async def _safe_clear_failures() -> None:
            try:
                await clear_failures(email)
            except Exception as exc:  # fail open on any lockout-store error
                logger.warning("lockout clear failed open (redis unavailable?): %s", exc)

        remaining = await _safe_is_locked()
        if remaining is not None:
            logger.warning(
                "auth_event LOGIN_LOCKED email=%s remaining_secs=%d",
                email, remaining,
            )
            raise AccountLockedException(retry_after=remaining)

        # B4/2.8: credential verification is delegated to an AuthProvider
        # resolved from the registry by method, so SSO/OIDC/SAML backends plug in
        # without changing this method. The default "password" provider owns email
        # normalisation, DB lookup, password verify, dummy-verify timing
        # equalisation, and transparent rehash. An unknown method fails closed as
        # a generic authentication error (no enumeration of available methods).
        provider = get_auth_provider(method)
        if provider is None:
            logger.warning("auth_event LOGIN_UNKNOWN_METHOD method=%s email=%s", method, email)
            raise AuthenticationError("Invalid credentials")
        outcome  = await provider.authenticate(
            credentials = {"email": email, "password": password},
            db          = db,
        )

        if not outcome.ok:
            reason = outcome.failure_reason or "invalid_credentials"
            matched = outcome.resolved_user
            if matched is None:
                await _safe_record_failure()
                logger.warning("auth_event LOGIN_FAILED email=%s reason=%s", email, reason)
                await _log_auth_event(
                    action         = "login_failed",
                    success        = False,
                    failure_reason = reason,
                    ip_address     = ip_address,
                    user_agent     = user_agent,
                )
            else:
                count, locked = await _safe_record_failure()
                logger.warning(
                    "auth_event LOGIN_FAILED email=%s reason=%s "
                    "attempt=%d is_now_locked=%s",
                    email, reason, count, locked,
                )
                _matched_mem = await _resolve_active_membership(db, matched.id)
                await _log_auth_event(
                    action         = "login_failed",
                    success        = False,
                    tenant_id      = _matched_mem.tenant_id if _matched_mem else None,
                    user_id        = matched.id,
                    failure_reason = reason,
                    ip_address     = ip_address,
                    user_agent     = user_agent,
                )
                # Notify on the TRANSITION into locked only (count == max), not
                # on every failure during the lockout window. Best-effort and
                # standalone: lockout state is in Redis, so there is no ambient
                # DB transaction to co-commit with.
                if locked and count == _settings.auth_max_failed_attempts:
                    from services.email.notifications import notify_account_locked
                    await notify_account_locked(
                        matched,
                        lockout_seconds = _settings.auth_lockout_duration_seconds,
                    )
            raise AuthenticationError()

        user = outcome.user

        if not user.is_active:
            logger.warning("auth_event LOGIN_FAILED email=%s reason=account_inactive", email)
            _inactive_mem = await _resolve_active_membership(db, user.id)
            await _log_auth_event(
                action         = "login_failed",
                success        = False,
                tenant_id      = _inactive_mem.tenant_id if _inactive_mem else None,
                user_id        = user.id,
                failure_reason = "account_inactive",
                ip_address     = ip_address,
                user_agent     = user_agent,
            )
            raise AccountDisabledException()

        # Resolve the membership this session is scoped to. Fail closed: a user
        # with no membership has no tenant/authz context, so no token is minted.
        active_membership = await _resolve_active_membership(db, user.id)
        if active_membership is None:
            logger.error("auth_event LOGIN_FAILED email=%s reason=no_membership", email)
            await _log_auth_event(
                action         = "login_failed",
                success        = False,
                user_id        = user.id,
                failure_reason = "no_membership",
                ip_address     = ip_address,
                user_agent     = user_agent,
            )
            raise AuthenticationError()

        await _safe_clear_failures()

        user_repo             = UserRepository(db)
        access_token          = create_access_token(user, active_membership)
        refresh_raw, ref_hash = create_refresh_token()
        expires_at            = _utcnow() + timedelta(days=_settings.jwt_refresh_token_expire_days)

        rt_repo = RefreshTokenRepository(db)
        await rt_repo.create(
            user_id       = user.id,
            token_hash    = ref_hash,
            expires_at    = _to_db(expires_at),
            token_version = user.token_version,
        )
        await user_repo.update_last_login(user.id)
        await db.commit()

        logger.info(
            "auth_event LOGIN_SUCCESS user_id=%s email=%s role=%s tenant_id=%s",
            user.id, user.email, active_membership.role, active_membership.tenant_id,
        )
        await _log_auth_event(
            action     = "login_success",
            success    = True,
            tenant_id  = active_membership.tenant_id,
            user_id    = user.id,
            ip_address = ip_address,
            user_agent = user_agent,
        )

        return LoginResult(
            access_token          = access_token,
            refresh_token         = refresh_raw,
            expires_in            = _settings.jwt_access_token_expire_minutes * 60,
            force_password_change = user.force_password_change,
            user                  = user,
            membership            = active_membership,
        )

    async def refresh(self, refresh_token_raw: str, db: AsyncSession) -> RefreshResult:
        from config.settings import get_settings
        from db.repositories.refresh_token import RefreshTokenRepository
        from db.repositories.user import UserRepository
        from errors.exceptions import InvalidTokenException, SessionInvalidatedException
        from services.auth.token import (
            create_access_token,
            create_refresh_token,
            hash_refresh_token,
        )

        _settings  = get_settings()
        token_hash = hash_refresh_token(refresh_token_raw)
        rt_repo    = RefreshTokenRepository(db)
        token_rec  = await rt_repo.get_by_hash(token_hash)

        if not token_rec:
            logger.warning("auth_event TOKEN_REFRESH_FAILED reason=refresh_failed")
            await _log_auth_event(
                action         = "token_refresh_failed",
                success        = False,
                failure_reason = "refresh_failed",
            )
            raise InvalidTokenException()

        # expires_at is TIMESTAMPTZ (aware UTC); compare against aware utc_now()
        if token_rec.expires_at and token_rec.expires_at < utc_now():
            await rt_repo.revoke(token_hash)
            await db.commit()
            logger.warning("auth_event TOKEN_REFRESH_FAILED reason=token_expired user_id=%s", token_rec.user_id)
            await _log_auth_event(
                action         = "token_refresh_failed",
                success        = False,
                user_id        = token_rec.user_id,
                failure_reason = "token_expired",
            )
            raise InvalidTokenException("Refresh token has expired.")

        user_repo = UserRepository(db)
        user      = await user_repo.get_by_id(token_rec.user_id)

        if not user or not user.is_active:
            await rt_repo.revoke(token_hash)
            await db.commit()
            logger.warning("auth_event TOKEN_REFRESH_FAILED reason=refresh_failed user_id=%s",
                           token_rec.user_id)
            await _log_auth_event(
                action         = "token_refresh_failed",
                success        = False,
                user_id        = token_rec.user_id,
                failure_reason = "refresh_failed",
            )
            raise InvalidTokenException("User not found or disabled")

        if token_rec.token_version != user.token_version:
            await rt_repo.revoke(token_hash)
            await db.commit()
            logger.warning(
                "auth_event TOKEN_REFRESH_FAILED user_id=%s reason=session_invalidated "
                "token_ver=%d user_ver=%d",
                user.id, token_rec.token_version, user.token_version,
            )
            _inv_mem = await _resolve_active_membership(db, user.id)
            await _log_auth_event(
                action         = "token_refresh_failed",
                success        = False,
                tenant_id      = _inv_mem.tenant_id if _inv_mem else None,
                user_id        = user.id,
                failure_reason = "session_invalidated",
            )
            raise SessionInvalidatedException()

        # Re-mint scoped to the user's active membership. Fail closed on none.
        active_membership = await _resolve_active_membership(db, user.id)
        if active_membership is None:
            await rt_repo.revoke(token_hash)
            await db.commit()
            logger.warning("auth_event TOKEN_REFRESH_FAILED user_id=%s reason=no_membership", user.id)
            await _log_auth_event(
                action         = "token_refresh_failed",
                success        = False,
                user_id        = user.id,
                failure_reason = "no_membership",
            )
            raise InvalidTokenException("User has no membership")

        new_access        = create_access_token(user, active_membership)
        new_raw, new_hash = create_refresh_token()
        expires_at        = _utcnow() + timedelta(days=_settings.jwt_refresh_token_expire_days)

        await rt_repo.revoke(token_hash)
        await rt_repo.create(
            user_id       = user.id,
            token_hash    = new_hash,
            expires_at    = _to_db(expires_at),
            token_version = user.token_version,
        )
        await db.commit()

        logger.info("auth_event TOKEN_REFRESH_SUCCESS user_id=%s", user.id)
        await _log_auth_event(
            action    = "token_refresh_success",
            success   = True,
            tenant_id = active_membership.tenant_id,
            user_id   = user.id,
        )

        return RefreshResult(
            access_token  = new_access,
            refresh_token = new_raw,
            expires_in    = _settings.jwt_access_token_expire_minutes * 60,
            user          = user,
            membership    = active_membership,
        )

    async def logout(
        self,
        refresh_token_raw: str,
        db:                AsyncSession,
        reason:            str = "manual",
    ) -> None:
        """
        Revokes refresh token and logs LOGOUT with reason.

        reason: pre-validated by endpoint (LogoutReason enum).
        Invalid values are normalized to "manual" at endpoint level -
        service trusts the reason passed in.

        Logging: non-blocking _log_auth_event(), best-effort.
        """
        from db.repositories.refresh_token import RefreshTokenRepository
        from services.auth.token import hash_refresh_token

        token_hash = hash_refresh_token(refresh_token_raw)
        rt_repo    = RefreshTokenRepository(db)
        token_rec  = await rt_repo.get_by_hash(token_hash)

        if token_rec:
            await rt_repo.revoke(token_hash)
            await db.commit()
            logger.info("auth_event LOGOUT user_id=%s reason=%s",
                        token_rec.user_id, reason)
            await _log_auth_event(
                action         = "logout",
                success        = True,
                user_id        = token_rec.user_id,
                failure_reason = reason,   # reason stored in failure_reason field
            )

    async def logout_all_sessions(self, user_id: UUID, db: AsyncSession) -> None:
        """
        Immediately invalidates ALL active sessions for a user.
        Increments token_version + revokes all refresh tokens atomically.
        MUST be called on: password change, role change, dept change,
        account deactivation, admin password reset.
        """
        from db.repositories.refresh_token import RefreshTokenRepository
        from db.repositories.user import UserRepository

        user_repo = UserRepository(db)
        rt_repo   = RefreshTokenRepository(db)

        new_ver = await user_repo.increment_token_version(user_id)
        revoked = await rt_repo.revoke_all_for_user(user_id)
        await db.commit()

        try:
            from cache.redis_client import get_redis
            await get_redis().delete(keyspace.auth_user(user_id))
        except Exception:
            pass  # stale cache will fail token_version check at next request

        logger.info(
            "auth_event SESSION_INVALIDATED user_id=%s "
            "new_token_version=%d refresh_tokens_revoked=%d",
            user_id, new_ver, revoked,
        )

    async def change_password(
        self,
        user_id:          UUID,
        current_password: str,
        new_password:     str,
        db:               AsyncSession,
    ) -> None:
        from db.repositories.user import UserRepository
        from errors.exceptions import AuthenticationError
        from services.auth.password import (
            hash_password,
            validate_password_strength,
            verify_password,
        )

        user_repo = UserRepository(db)
        user      = await user_repo.get_by_id(user_id)

        if not user:
            raise AuthenticationError("User not found")

        if not verify_password(current_password, user.password_hash):
            raise AuthenticationError("Current password is incorrect")

        validate_password_strength(new_password)

        await user_repo.update(user_id, {
            "password_hash":         hash_password(new_password),
            "force_password_change": False,
        })
        # Enqueue the password-changed notification on THIS session so the
        # outbox row commits atomically with the password change below. Enqueue
        # is a local INSERT (SMTP is not touched here), so it never couples the
        # change to email delivery; a render failure is swallowed internally.
        from services.email.notifications import notify_password_changed
        await notify_password_changed(db, user)
        # No intermediate commit - password hash update and session invalidation
        # (token_version increment + refresh token revocations) must be committed
        # atomically. logout_all_sessions() issues the single commit.
        await self.logout_all_sessions(user_id, db)

        logger.info("auth_event PASSWORD_CHANGED user_id=%s", user_id)
