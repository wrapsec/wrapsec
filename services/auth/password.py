# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

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
# NEVER change the sentinel string "__wrapsec_timing_dummy__" - only update
# the hash value if you do (and update the unit test too).
_DUMMY_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TiGrmlfebYcSGR/Q3pnK.Bj2SL8."


def normalize_email(email: str) -> str:
    """
    Normalizes email to lowercase + stripped whitespace.

    MUST be called before:
    - Every DB write  (user creation, bootstrap, password reset)
    - Every DB read   (login lookup, existence check)

    Ensures User@Company.com and user@company.com are treated as identical.
    The ux_users_email_lower index stores LOWER(email) - all queries must match.
    """
    return email.lower().strip()


_MAX_PASSWORD_LEN = 128

# Top common passwords that pass basic character-variety checks.
# Stored lowercase - comparison uses password.lower() so case variants are caught.
_COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password1", "password12", "password123", "password1234",
    "passw0rd", "p@ssword1", "p@ssw0rd",
    "admin123", "admin1234", "admin@123",
    "welcome1", "welcome12", "welcome123",
    "qwerty123", "qwerty12", "qwerty1",
    "abc123456", "abcd1234", "abcde123",
    "letmein1", "letmein12",
    "iloveyou1", "iloveyou12",
    "monkey123", "monkey12",
    "dragon123", "dragon12",
    "master123", "master12",
    "sunshine1", "sunshine12",
    "princess1",
    "football1", "football12",
    "baseball1",
    "superman1", "superman12",
    "batman123",
    "trustno1",
    "hello123", "hello1234",
    "shadow123",
    "michael1",
    "mustang1",
    "access123",
    "login123",
    "test1234", "test@123",
    "changeme1", "changeme123",
    "secret123",
    "wrapsec1", "wrapsec123",
})


def hash_password(password: str) -> str:
    """
    Returns bcrypt hash of the given password.
    Always call validate_password_strength() before this.
    NEVER store the result of this function in logs.
    """
    if len(password) > _MAX_PASSWORD_LEN:
        raise ValueError(f"Password must not exceed {_MAX_PASSWORD_LEN} characters")
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Constant-time bcrypt comparison via passlib.
    Timing-safe - bcrypt work factor equalises comparison time across inputs.

    Passwords exceeding _MAX_PASSWORD_LEN are rejected immediately - bcrypt
    only processes the first 72 bytes, so over-length inputs can never match
    a hash produced by hash_password() which enforces the same limit.
    """
    if len(plain) > _MAX_PASSWORD_LEN:
        return False
    return pwd_context.verify(plain, hashed)


def verify_dummy() -> None:
    """
    Runs a dummy bcrypt verify against _DUMMY_HASH.

    MUST be called when user is not found in the login flow - immediately
    before raising InvalidCredentialsException. This equalises response
    timing between the 'user not found' and 'wrong password' paths.

    Without this: response time differs because bcrypt verify is slow (~100ms)
    but a missing-user path skips it entirely, leaking whether an email address
    is registered via response time measurement (timing oracle / enumeration).

    Sentinel input "__dummy_input__" is intentionally different from
    "__wrapsec_timing_dummy__" - it will never match _DUMMY_HASH, so
    verify() always returns False. That is correct and expected.
    """
    pwd_context.verify("__dummy_input__", _DUMMY_HASH)


def validate_password_strength(password: str) -> None:
    """
    Raises ValueError with descriptive message if password does not meet
    minimum strength requirements.

    Call before hash_password() on: user creation, password change, bootstrap.

    Requirements:
        - At most 128 characters (bcrypt DoS prevention)
        - At least 8 characters
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 1 digit
        - At least 4 unique characters (prevents repetitive patterns)
        - Not a known-common password
    """
    if len(password) > _MAX_PASSWORD_LEN:
        raise ValueError(f"Password must not exceed {_MAX_PASSWORD_LEN} characters")
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
    if len(set(password)) < 4:
        raise ValueError("Password must contain at least 4 different characters")
    if password.lower() in _COMMON_PASSWORDS:
        raise ValueError("Password is too common. Please choose a more unique password.")
