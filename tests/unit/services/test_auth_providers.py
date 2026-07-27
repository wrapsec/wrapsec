# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
B4 in v1.1.0 -- AuthProvider interface + PasswordAuthProvider.

These tests lock in the provider contract: authenticate() must return
AuthenticationOutcome (never raise on bad credentials), and must be
timing-safe against user enumeration.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.auth.providers import (
    AuthenticationOutcome,
    PasswordAuthProvider,
)


@pytest.mark.asyncio
async def test_success_returns_user_and_no_failure_reason():
    fake_user = SimpleNamespace(
        id="00000000-0000-0000-0000-000000000001",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$abcdef$xxxxxx",
    )
    repo_instance = MagicMock()
    repo_instance.get_by_email = AsyncMock(return_value=fake_user)
    repo_instance.update       = AsyncMock()

    with patch(
        "db.repositories.user.UserRepository", return_value=repo_instance
    ), patch(
        "services.auth.password.verify_password", return_value=True
    ), patch(
        "services.auth.password.needs_rehash", return_value=False
    ):
        outcome = await PasswordAuthProvider().authenticate(
            {"email": "user@example.com", "password": "SecurePass1"},
            db=MagicMock(),
        )

    assert outcome.ok is True
    assert outcome.user is fake_user
    assert outcome.failure_reason is None


@pytest.mark.asyncio
async def test_user_not_found_runs_dummy_verify_and_returns_reason():
    repo_instance = MagicMock()
    repo_instance.get_by_email = AsyncMock(return_value=None)

    with patch(
        "db.repositories.user.UserRepository", return_value=repo_instance
    ), patch(
        "services.auth.password.verify_dummy"
    ) as dummy:
        outcome = await PasswordAuthProvider().authenticate(
            {"email": "ghost@example.com", "password": "whatever"},
            db=MagicMock(),
        )

    # Timing equalisation - dummy verify MUST run on the unknown-user path
    dummy.assert_called_once()
    assert outcome.ok is False
    assert outcome.user is None
    assert outcome.resolved_user is None
    assert outcome.failure_reason == "user_not_found"


@pytest.mark.asyncio
async def test_wrong_password_returns_resolved_user_for_logging():
    fake_user = SimpleNamespace(
        id="00000000-0000-0000-0000-000000000002",
        tenant_id="00000000-0000-0000-0000-000000000099",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$abcdef$xxxxxx",
    )
    repo_instance = MagicMock()
    repo_instance.get_by_email = AsyncMock(return_value=fake_user)

    with patch(
        "db.repositories.user.UserRepository", return_value=repo_instance
    ), patch(
        "services.auth.password.verify_password", return_value=False
    ):
        outcome = await PasswordAuthProvider().authenticate(
            {"email": "user@example.com", "password": "WrongPass1"},
            db=MagicMock(),
        )

    assert outcome.ok is False
    # resolved_user is required so AuthService can log tenant_id + user_id
    assert outcome.resolved_user is fake_user
    assert outcome.failure_reason == "invalid_password"


@pytest.mark.asyncio
async def test_success_triggers_rehash_on_deprecated_scheme():
    fake_user = SimpleNamespace(
        id="00000000-0000-0000-0000-000000000003",
        password_hash="$2b$12$legacybcrypthashxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    )
    repo_instance = MagicMock()
    repo_instance.get_by_email = AsyncMock(return_value=fake_user)
    repo_instance.update       = AsyncMock()

    with patch(
        "db.repositories.user.UserRepository", return_value=repo_instance
    ), patch(
        "services.auth.password.verify_password", return_value=True
    ), patch(
        "services.auth.password.needs_rehash", return_value=True
    ), patch(
        "services.auth.password.hash_password", return_value="$argon2id$new$hash"
    ):
        outcome = await PasswordAuthProvider().authenticate(
            {"email": "user@example.com", "password": "SecurePass1"},
            db=MagicMock(),
        )

    assert outcome.ok is True
    # rehash writes the new hash back through repo.update()
    repo_instance.update.assert_awaited_once()
    args = repo_instance.update.await_args
    assert args.args[1]["password_hash"].startswith("$argon2id$")


@pytest.mark.asyncio
async def test_rehash_failure_does_not_deny_login():
    fake_user = SimpleNamespace(
        id="00000000-0000-0000-0000-000000000004",
        password_hash="$2b$12$legacybcrypthashxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    )
    repo_instance = MagicMock()
    repo_instance.get_by_email = AsyncMock(return_value=fake_user)
    repo_instance.update       = AsyncMock(side_effect=RuntimeError("db down"))

    with patch(
        "db.repositories.user.UserRepository", return_value=repo_instance
    ), patch(
        "services.auth.password.verify_password", return_value=True
    ), patch(
        "services.auth.password.needs_rehash", return_value=True
    ), patch(
        "services.auth.password.hash_password", return_value="$argon2id$new$hash"
    ):
        outcome = await PasswordAuthProvider().authenticate(
            {"email": "user@example.com", "password": "SecurePass1"},
            db=MagicMock(),
        )

    # Login must succeed even though the rehash write failed
    assert outcome.ok is True
    assert outcome.user is fake_user


def test_provider_name_is_stable():
    """Log/metric consumers key off provider.name; changing it is a break."""
    assert PasswordAuthProvider().name == "password"


def test_outcome_ok_property():
    assert AuthenticationOutcome(user="u").ok is True
    assert AuthenticationOutcome(failure_reason="x").ok is False
    assert AuthenticationOutcome(resolved_user="u", failure_reason="x").ok is False
