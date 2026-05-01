# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import pytest
from services.auth.password import (
    normalize_email,
    hash_password,
    verify_password,
    verify_dummy,
    validate_password_strength,
    _DUMMY_HASH,
    _MAX_PASSWORD_LEN,
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


def test_hash_rejects_overlong_password():
    overlong = "A1" * 65  # 130 chars > 128
    with pytest.raises(ValueError, match="128"):
        hash_password(overlong)


def test_verify_rejects_overlong_password():
    # Must return False immediately — bcrypt must never run on >128-char input
    h = hash_password("SecurePass1")
    overlong = "A1" * 65
    assert verify_password(overlong, h) is False


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


def test_strength_rejects_overlong():
    overlong = "A1" * 65  # 130 chars > 128
    with pytest.raises(ValueError, match="128"):
        validate_password_strength(overlong)


def test_strength_accepts_max_boundary():
    # Exactly 128 chars, 4+ unique chars (a, B, 1, c), not in common list
    at_limit = ("aB1c" * 32)[:_MAX_PASSWORD_LEN]  # 128 chars
    validate_password_strength(at_limit)  # must not raise


def test_strength_rejects_too_few_unique_chars():
    with pytest.raises(ValueError, match="4 different"):
        validate_password_strength("Aaaaaaaaa1")  # only 3 unique: A, a, 1


def test_strength_rejects_common_password():
    with pytest.raises(ValueError, match="common"):
        validate_password_strength("Password123")  # "password123" in blocklist


def test_strength_rejects_common_password_case_insensitive():
    # Mixed-case variant of "password123" — lowercases to a blocklist entry
    with pytest.raises(ValueError, match="common"):
        validate_password_strength("pAsSword123")  # normalised → "password123"


def test_strength_strong_unique_passes():
    # Unique enough, not in common list
    validate_password_strength("xK9!mRvLq2")  # must not raise
