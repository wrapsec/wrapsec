# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add tenant_settings and platform_settings (settings split, expand phase)

Revision ID: 0017_settings_split
Revises: 0016_users_identity_only
Create Date: 2026-08-14

Settings model D5/D1 two-table split, expand phase (C2a). Introduces:
  - tenant_settings   (tenant_id, key) -- per-tenant config
  - platform_settings (key)            -- platform / control-plane config

Additive: the old global `settings` table is left in place and keeps working
until the contract phase. On an existing database the current settings rows are
copied into tenant_settings under the default tenant so nothing is lost when the
readers switch over. Guarded/idempotent:
  - On a fresh model-driven baseline (0001 create_all) both new tables already
    exist, so the creates are skipped.
  - The backfill runs only when the old `settings` table still has rows and a
    default tenant exists; ON CONFLICT DO NOTHING makes a re-run safe.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017_settings_split"
down_revision: str | None = "0016_users_identity_only"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _create_platform_settings() -> None:
    op.create_table(
        "platform_settings",
        sa.Column("key",   sa.String(100), primary_key=True),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )


def _create_tenant_settings() -> None:
    op.create_table(
        "tenant_settings",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key",       sa.String(100), nullable=False),
        sa.Column("value",     sa.Text, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("tenant_id", "key"),
    )


def upgrade() -> None:
    bind   = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())

    if "platform_settings" not in tables:
        _create_platform_settings()
    if "tenant_settings" not in tables:
        _create_tenant_settings()

    # Backfill from the legacy global settings table (existing DBs only).
    tables = set(sa.inspect(bind).get_table_names())
    if bind.dialect.name == "postgresql" and "settings" in tables:
        default_tid = bind.execute(
            sa.text("SELECT id FROM tenants WHERE slug = 'default' LIMIT 1")
        ).scalar()
        if default_tid is not None:
            op.execute(
                sa.text(
                    "INSERT INTO tenant_settings (tenant_id, key, value, updated_at) "
                    "SELECT :tid, key, value, updated_at FROM settings "
                    "ON CONFLICT (tenant_id, key) DO NOTHING"
                ).bindparams(tid=default_tid)
            )


def downgrade() -> None:
    bind   = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "tenant_settings" in tables:
        op.drop_table("tenant_settings")
    if "platform_settings" in tables:
        op.drop_table("platform_settings")
