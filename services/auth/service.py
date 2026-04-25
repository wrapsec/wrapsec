import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("wrapsec.auth")


def _utcnow() -> datetime:
    """
    Returns current UTC time as a timezone-aware datetime.
    Use this everywhere in the auth service for internal calculations.
    """
    return datetime.now(timezone.utc)


def _to_db(dt: datetime) -> datetime:
    """
    Strips timezone info before writing to DB.
    DB columns are TIMESTAMP WITHOUT TIME ZONE — asyncpg rejects aware datetimes.
    All datetimes stored in DB are implicitly UTC.

    Usage: always wrap datetime values going INTO the DB with this function.
    Datetimes coming OUT of the DB are naive — compare with datetime.utcnow().
    """
    return dt.replace(tzinfo=None)


@dataclass
class LoginResult:
    access_token:          str
    refresh_token:         str    # raw token — caller sets as httpOnly cookie
    expires_in:            int    # seconds until access token expiry
    force_password_change: bool
    user:                  object  # UserModel — typed as object to avoid circular import


@dataclass
class RefreshResult:
    access_token:  str
    refresh_token: str  # new rotated raw token
    expires_in:    int


class AuthService:

    async def login(self, email: str, password: str, db: AsyncSession) -> LoginResult:
        """
        Full login flow. Steps are in order — do not reorder.

        Step 1  — normalize_email()
        Step 2  — is_locked() → 429 if locked (no DB query — fast path)
        Step 3  — get_by_email() from DB
        Step 4  — If not found: verify_dummy() [MANDATORY timing eq] + record_failure + 401
        Step 5  — verify_password() — constant-time bcrypt
        Step 6  — If wrong: record_failure + 401
        Step 7  — If not is_active: 401 ACCOUNT_DISABLED (no failure recorded)
        Step 8  — clear_failures()
        Step 9  — create_access_token()
        Step 10 — create_refresh_token() → (raw, hash)
        Step 11 — [TRANSACTION]
                    RefreshTokenRepository.create(token_version=user.token_version)
                    UserRepository.update_last_login()
                  [db.commit() — single atomic commit]
        Step 12 — Log LOGIN_SUCCESS
        Step 13 — Return LoginResult
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

        # Step 2 — lockout check (Redis only, no DB)
        if await is_locked(email):
            remaining = await get_lockout_remaining(email)
            logger.warning(
                "auth_event LOGIN_LOCKED email=%s remaining_secs=%d",
                email, remaining,
            )
            raise AccountLockedException(retry_after=remaining)

        # Step 3 — DB lookup
        user_repo = UserRepository(db)
        user      = await user_repo.get_by_email(email)

        # Step 4 — user not found (timing equalisation MANDATORY)
        if not user:
            verify_dummy()  # equalises timing vs wrong_password path
            await record_failure(email)
            logger.warning(
                "auth_event LOGIN_FAILED email=%s reason=user_not_found", email
            )
            raise AuthenticationError()

        # Step 5+6 — verify password
        if not verify_password(password, user.password_hash):
            count, locked = await record_failure(email)
            logger.warning(
                "auth_event LOGIN_FAILED email=%s reason=wrong_password "
                "attempt=%d is_now_locked=%s",
                email, count, locked,
            )
            raise AuthenticationError()

        # Step 7 — active check
        if not user.is_active:
            logger.warning(
                "auth_event LOGIN_FAILED email=%s reason=account_disabled", email
            )
            raise AccountDisabledException()

        # Step 8 — clear lockout on success
        await clear_failures(email)

        # Step 9+10 — create tokens
        access_token          = create_access_token(user)
        refresh_raw, ref_hash = create_refresh_token()

        # Timezone-aware internally — stripped to naive at DB boundary via _to_db()
        expires_at = _utcnow() + timedelta(days=_settings.jwt_refresh_token_expire_days)

        # Step 11 — single transaction: create refresh token + update last login
        rt_repo = RefreshTokenRepository(db)
        await rt_repo.create(
            user_id       = user.id,
            token_hash    = ref_hash,
            expires_at    = _to_db(expires_at),   # naive UTC for DB
            token_version = user.token_version,
        )
        await user_repo.update_last_login(user.id)
        await db.commit()

        # Step 12 — log success
        logger.info(
            "auth_event LOGIN_SUCCESS user_id=%s email=%s role=%s tenant_id=%s",
            user.id, user.email, user.role, user.tenant_id,
        )

        return LoginResult(
            access_token          = access_token,
            refresh_token         = refresh_raw,
            expires_in            = _settings.jwt_access_token_expire_minutes * 60,
            force_password_change = user.force_password_change,
            user                  = user,
        )

    async def refresh(self, refresh_token_raw: str, db: AsyncSession) -> RefreshResult:
        """
        Rotates refresh token and issues new access token.
        Race condition protection: get_by_hash() uses SELECT FOR UPDATE.
        """
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

        rt_repo   = RefreshTokenRepository(db)
        token_rec = await rt_repo.get_by_hash(token_hash)  # SELECT FOR UPDATE

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
                "auth_event SESSION_INVALIDATED user_id=%s "
                "token_ver=%d user_ver=%d",
                user.id, token_rec.token_version, user.token_version,
            )
            raise SessionInvalidatedException()

        new_access        = create_access_token(user)
        new_raw, new_hash = create_refresh_token()

        expires_at = _utcnow() + timedelta(days=_settings.jwt_refresh_token_expire_days)

        # Single transaction — revoke old and create new atomically
        await rt_repo.revoke(token_hash)
        await rt_repo.create(
            user_id       = user.id,
            token_hash    = new_hash,
            expires_at    = _to_db(expires_at),   # naive UTC for DB
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
        """
        Revokes the provided refresh token.
        Idempotent — safe with already-revoked or not-found token.
        """
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

        MUST be called on: password change, role change, deactivation, admin reset.
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
        """
        Changes password and invalidates all sessions.
        """
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
        await db.commit()

        await self.logout_all_sessions(user_id, db)

        logger.info("auth_event PASSWORD_CHANGED user_id=%s", user_id)
