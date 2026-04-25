from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pre-computed bcrypt hash used for timing equalisation in login().
#
# WHY hardcoded (R5 fix):
#   A dynamically computed hash (pwd_context.hash(...) at module load time)
#   produces a different hash on every process restart, introducing slight
#   timing variation between restarts. A hardcoded hash is fully stable.
#
# HOW to regenerate if needed:
#   from passlib.context import CryptContext
#   print(CryptContext(["bcrypt"]).hash("__wrapsec_timing_dummy__"))
#
# NEVER change the sentinel string "__wrapsec_timing_dummy__" — only update
# the hash value if you do (and update the unit test too).
_DUMMY_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TiGrmlfebYcSGR/Q3pnK.Bj2SL8."


def normalize_email(email: str) -> str:
    """
    Normalizes email to lowercase + stripped whitespace.

    MUST be called before:
    - Every DB write  (user creation, bootstrap, password reset)
    - Every DB read   (login lookup, existence check)

    Ensures User@Company.com and user@company.com are treated as identical.
    The ux_users_email_lower index stores LOWER(email) — all queries must match.
    """
    return email.lower().strip()


def hash_password(password: str) -> str:
    """
    Returns bcrypt hash of the given password.
    Always call validate_password_strength() before this.
    NEVER store the result of this function in logs.
    """
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Constant-time bcrypt comparison via passlib.
    Timing-safe — bcrypt work factor equalises comparison time across inputs.
    """
    return pwd_context.verify(plain, hashed)


def verify_dummy() -> None:
    """
    Runs a dummy bcrypt verify against _DUMMY_HASH.

    MUST be called when user is not found in the login flow — immediately
    before raising InvalidCredentialsException. This equalises response
    timing between the 'user not found' and 'wrong password' paths.

    Without this: response time differs because bcrypt verify is slow (~100ms)
    but a missing-user path skips it entirely, leaking whether an email address
    is registered via response time measurement (timing oracle / enumeration).

    Sentinel input "__dummy_input__" is intentionally different from
    "__wrapsec_timing_dummy__" — it will never match _DUMMY_HASH, so
    verify() always returns False. That is correct and expected.
    """
    pwd_context.verify("__dummy_input__", _DUMMY_HASH)


def validate_password_strength(password: str) -> None:
    """
    Raises ValueError with descriptive message if password does not meet
    minimum strength requirements.

    Call before hash_password() on: user creation, password change, bootstrap.

    Requirements:
        - At least 8 characters
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 1 digit
    """
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not any(c.isupper() for c in password):
        errors.append("at least one uppercase letter")
    if not any(c.islower() for c in password):
        errors.append("at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        errors.append("at least one digit")
    if errors:
        raise ValueError(f"Password must contain: {', '.join(errors)}")
