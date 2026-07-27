# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""reencrypt stored secrets from v1 to v2 envelope format

Revision ID: 0002_reencrypt_secrets_v2_envelope
Revises: 0001_baseline
Create Date: 2026-07-27

Rewrites every AES-256-GCM ciphertext produced before v1.1.0 into the new
envelope-encryption format (B3). Touches every place a v1 blob can live:

  - proxy_provider_configs.provider_api_key_enc  (column)
  - settings.value ->> 'enc'                     (JSON, key=llm_api_key_enc)
  - departments.policy_override ->> llm.api_key_enc
  - departments.policy_override ->> proxy_provider.api_key_enc
  - applications.policy_override ->> llm.api_key_enc
  - applications.policy_override ->> proxy_provider.api_key_enc

Rows already in v2 format (marker prefix "v2:") are skipped so re-running
this migration is a no-op. Rows we cannot decrypt (wrong SECRET_KEY,
corrupt data) are logged and left untouched -- an unreadable secret was
already unreadable before this migration and the runtime treats it as
"no configured key" anyway.
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from security.encryption import decrypt, encrypt


revision: str = "0002_reencrypt_secrets_v2_envelope"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_V2_PREFIX  = "v2:"
_SECRET_KEY: str | None = None

logger = logging.getLogger("alembic.migration.0002")


def _secret() -> str:
    global _SECRET_KEY
    if _SECRET_KEY is None:
        from config.settings import get_settings
        _SECRET_KEY = get_settings().secret_key
    return _SECRET_KEY


def _reencrypt(value: str | None) -> str | None:
    """Return a v2 ciphertext for `value`, or the original on skip/failure."""
    if not value or value.startswith(_V2_PREFIX):
        return value
    try:
        plaintext = decrypt(value, _secret())
    except ValueError as exc:
        logger.warning("skipping unreadable ciphertext: %s", exc)
        return value
    return encrypt(plaintext, _secret())


def _rewrite_nested_api_key_enc(policy: dict | None) -> tuple[dict | None, bool]:
    """
    Walk a policy_override dict and rewrite api_key_enc in each known
    subsection. Returns (new_policy, changed).
    """
    if not isinstance(policy, dict):
        return policy, False
    changed = False
    for section_key in ("llm", "proxy_provider"):
        section = policy.get(section_key)
        if not isinstance(section, dict):
            continue
        enc = section.get("api_key_enc")
        new_enc = _reencrypt(enc)
        if new_enc != enc:
            section["api_key_enc"] = new_enc
            changed = True
    return policy, changed


def upgrade() -> None:
    bind = op.get_bind()

    # 1) proxy_provider_configs.provider_api_key_enc ---------------------------
    rows = bind.execute(sa.text(
        "SELECT id, provider_api_key_enc FROM proxy_provider_configs "
        "WHERE provider_api_key_enc IS NOT NULL "
        "AND provider_api_key_enc NOT LIKE 'v2:%'"
    )).fetchall()
    for row_id, enc in rows:
        new_enc = _reencrypt(enc)
        if new_enc != enc:
            bind.execute(
                sa.text(
                    "UPDATE proxy_provider_configs SET provider_api_key_enc = :v "
                    "WHERE id = :id"
                ),
                {"v": new_enc, "id": row_id},
            )

    # 2) settings.value (JSON/JSONB) where key = 'llm_api_key_enc' ------------
    rows = bind.execute(sa.text(
        "SELECT key, value FROM settings WHERE key = 'llm_api_key_enc'"
    )).fetchall()
    for key, value in rows:
        if not isinstance(value, dict):
            continue
        enc     = value.get("enc")
        new_enc = _reencrypt(enc)
        if new_enc != enc:
            value["enc"] = new_enc
            bind.execute(
                sa.text("UPDATE settings SET value = :v WHERE key = :k"),
                {"v": value, "k": key},
            )

    # 3) departments.policy_override and 4) applications.policy_override ------
    for table in ("departments", "applications"):
        rows = bind.execute(sa.text(
            f"SELECT id, policy_override FROM {table} "
            f"WHERE policy_override IS NOT NULL"
        )).fetchall()
        for row_id, policy in rows:
            new_policy, changed = _rewrite_nested_api_key_enc(policy)
            if changed:
                bind.execute(
                    sa.text(
                        f"UPDATE {table} SET policy_override = :v WHERE id = :id"
                    ),
                    {"v": new_policy, "id": row_id},
                )


def downgrade() -> None:
    # v2 -> v1 downgrade is intentionally unsupported. v1 uses a single derived
    # AES key with no envelope; we cannot recover that path from a v2 ciphertext
    # without re-encrypting, and the whole point of B3 is to move off v1.
    raise RuntimeError(
        "0002_reencrypt_secrets_v2_envelope is a one-way migration; "
        "restore from backup instead of downgrading."
    )
