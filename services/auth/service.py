import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("wrapsec.auth")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_db(dt: datetime) -> datetime:
    return dt.replace(tzinfo=None)


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

    Non-blocking by design: uses an independent session — never touches the
    request session and cannot delay the login response.
    Best-effort: any exception is logged internally and suppressed.

    tenant_id / user_id:
        Known user   → set from user record
        Unknown user → both None (user not found, cannot resolve tenant)
    """
    try:
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
        from sqlalchemy.pool import NullPool
        from config.settings import get_settings
        from db.models import AuthEventModel

        _settings = get_settings()
        engine    = create_async_engine(_settings.database_url, poolclass=NullPool)
        sf        = async_sessionmaker(bind=engine, class_=AsyncSession,
                                        expire_on_commit=False)

        async with sf() as session:
            event = AuthEventModel(
                tenant_id      = tenant_id,
                user_id        = user_id,
                action         = action,
                success        = success,
                failure_reason = failure_reason,
                ip_address     = ip_address,
                user_agent     = user_agent,
            )
            session.add(event)
            await session.commit()

        await engine.dispose()

    except Exception as e:
        logger.error("auth_event DB logging failed action=%s error=%s", action, e)


@dataclass
class LoginResult:
    access_token:          str
    refresh_token:         str
    expires_in:            int
    force_password_change: bool
    user:                  object


@dataclass
class RefreshResult:
    access_token:  str
    refresh_token: str
    expires_in:    int


class AuthService:

    async def login(
        self,
        email:      str,
        password:   str,
        db:         AsyncSession,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> LoginResult:
        """
        Full login flow.

        ip_address and user_agent are optional — passed from the request for
        auth_events logging. Login succeeds regardless of their presence.

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
        from services.auth.password import normalize_email, verify_dummy, verify_password
        from services.auth.token import create_access_token, create_refresh_token

        _settings = get_settings()
        email     = normalize_email(email)

        if await is_locked(email):
            remaining = await get_lockout_remaining(email)
            logger.warning(
                "auth_event LOGIN_LOCKED email=%s remaining_secs=%d",
                email, remaining,
            )
            raise AccountLockedException(retry_after=remaining)

        user_repo = UserRepository(db)
        user      = await user_repo.get_by_email(email)

        if not user:
            verify_dummy()
            await record_failure(email)
            logger.warning("auth_event LOGIN_FAILED email=%s reason=user_not_found", email)
            await _log_auth_event(
                action         = "login_failed",
                success        = False,
                failure_reason = "user_not_found",
                ip_address     = ip_address,
                user_agent     = user_agent,
            )
            raise AuthenticationError()

        if not verify_password(password, user.password_hash):
            count, locked = await record_failure(email)
            logger.warning(
                "auth_event LOGIN_FAILED email=%s reason=wrong_password "
                "attempt=%d is_now_locked=%s",
                email, count, locked,
            )
            await _log_auth_event(
                action         = "login_failed",
                success        = False,
                tenant_id      = user.tenant_id,
                user_id        = user.id,
                failure_reason = "invalid_password",
                ip_address     = ip_address,
                user_agent     = user_agent,
            )
            raise AuthenticationError()

        if not user.is_active:
            logger.warning("auth_event LOGIN_FAILED email=%s reason=account_inactive", email)
            await _log_auth_event(
                action         = "login_failed",
                success        = False,
                tenant_id      = user.tenant_id,
                user_id        = user.id,
                failure_reason = "account_inactive",
                ip_address     = ip_address,
                user_agent     = user_agent,
            )
            raise AccountDisabledException()

        await clear_failures(email)

        access_token          = create_access_token(user)
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
            user.id, user.email, user.role, user.tenant_id,
        )
        await _log_auth_event(
            action     = "login_success",
            success    = True,
            tenant_id  = user.tenant_id,
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
        )

    async def refresh(self, refresh_token_raw: str, db: AsyncSession) -> RefreshResult:
        from config.settings import get_settings
        from db.repositories.refresh_token import RefreshTokenRepository
        from db.repositories.user import UserRepository
        from errors.exceptions import InvalidTokenException, SessionInvalidatedException
        from services.auth.token import (
            create_access_token, create_refresh_token, hash_refresh_token,
        )

        _settings  = get_settings()
        token_hash = hash_refresh_token(refresh_token_raw)
        rt_repo    = RefreshTokenRepository(db)
        token_rec  = await rt_repo.get_by_hash(token_hash)

        if not token_rec:
            raise InvalidTokenException()

        user_repo = UserRepository(db)
        user      = await user_repo.get_by_id(token_rec.user_id)

        if not user or not user.is_active:
            await rt_repo.revoke(token_hash)
            await db.commit()
            raise InvalidTokenException("User not found or disabled")

        if token_rec.token_version != user.token_version:
            await rt_repo.revoke(token_hash)
            await db.commit()
            logger.warning(
                "auth_event SESSION_INVALIDATED user_id=%s token_ver=%d user_ver=%d",
                user.id, token_rec.token_version, user.token_version,
            )
            raise SessionInvalidatedException()

        new_access        = create_access_token(user)
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

        logger.info("auth_event TOKEN_REFRESHED user_id=%s", user.id)

        return RefreshResult(
            access_token  = new_access,
            refresh_token = new_raw,
            expires_in    = _settings.jwt_access_token_expire_minutes * 60,
        )

    async def logout(self, refresh_token_raw: str, db: AsyncSession) -> None:
        from db.repositories.refresh_token import RefreshTokenRepository
        from services.auth.token import hash_refresh_token

        token_hash = hash_refresh_token(refresh_token_raw)
        rt_repo    = RefreshTokenRepository(db)
        token_rec  = await rt_repo.get_by_hash(token_hash)

        if token_rec:
            await rt_repo.revoke(token_hash)
            await db.commit()
            logger.info("auth_event LOGOUT user_id=%s", token_rec.user_id)

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
            hash_password, validate_password_strength, verify_password,
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
        await db.commit()

        await self.logout_all_sessions(user_id, db)

        logger.info("auth_event PASSWORD_CHANGED user_id=%s", user_id)
