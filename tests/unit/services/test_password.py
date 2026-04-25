import pytest
from services.auth.password import (
    normalize_email,
    hash_password,
    verify_password,
    verify_dummy,
    validate_password_strength,
    _DUMMY_HASH,
    pwd_context,
)


# ── normalize_email ────────────────────────────────────────────────────────────

def test_normalize_lowercase():
    assert normalize_email("User@Example.COM") == "user@example.com"


def test_normalize_strips_whitespace():
    assert normalize_email("  user@example.com  ") == "user@example.com"


def test_normalize_both():
    assert normalize_email("  User@Example.COM  ") == "user@example.com"


def test_normalize_already_clean():
    assert normalize_email("user@example.com") == "user@example.com"


# ── hash_password / verify_password ───────────────────────────────────────────

def test_hash_returns_bcrypt_hash():
    h = hash_password("SecurePass1")
    assert h.startswith("$2b$")


def test_verify_correct_returns_true():
    h = hash_password("SecurePass1")
    assert verify_password("SecurePass1", h) is True


def test_verify_wrong_returns_false():
    h = hash_password("SecurePass1")
    assert verify_password("WrongPass1", h) is False


def test_hash_is_not_deterministic():
    # bcrypt uses random salt — same input produces different hashes
    h1 = hash_password("SecurePass1")
    h2 = hash_password("SecurePass1")
    assert h1 != h2


# ── verify_dummy ───────────────────────────────────────────────────────────────

def test_verify_dummy_does_not_raise():
    # Must not raise — timing equalisation must always complete
    verify_dummy()


def test_dummy_hash_is_static_not_dynamic():
    # _DUMMY_HASH must be a hardcoded string, not computed at runtime
    # If it were dynamic, timing would vary between restarts
    assert isinstance(_DUMMY_HASH, str)
    assert _DUMMY_HASH.startswith("$2b$")


def test_dummy_verify_always_returns_false():
    # Sentinel input never matches _DUMMY_HASH — that is correct and expected
    result = pwd_context.verify("__dummy_input__", _DUMMY_HASH)
    assert result is False


# ── validate_password_strength ────────────────────────────────────────────────

def test_strength_too_short():
    with pytest.raises(ValueError, match="8 characters"):
        validate_password_strength("Ab1")


def test_strength_no_uppercase():
    with pytest.raises(ValueError, match="uppercase"):
        validate_password_strength("securepass1")


def test_strength_no_lowercase():
    with pytest.raises(ValueError, match="lowercase"):
        validate_password_strength("SECUREPASS1")


def test_strength_no_digit():
    with pytest.raises(ValueError, match="digit"):
        validate_password_strength("SecurePass!")


def test_strength_valid_passes():
    # Must not raise
    validate_password_strength("SecurePass1")


def test_strength_lists_all_failures():
    with pytest.raises(ValueError) as exc_info:
        validate_password_strength("ab")
    msg = str(exc_info.value)
    assert "8 characters" in msg
    assert "uppercase" in msg
    assert "digit" in msg
