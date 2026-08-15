# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add tenant_id/dept_id/app_id to proxy_interactions (tenant attribution)

Revision ID: 0019_proxy_interactions_tenant
Revises: 0018_drop_legacy_settings
Create Date: 2026-08-14

M5 tenant attribution: proxy_interactions now stores tenant_id/dept_id/app_id
directly, so tenant scoping filters the row instead of joining api_keys -- a
revoked or deleted key no longer erases its interaction history. Adds an index
on (tenant_id, created_at) for the scoped listing.

Additive and guarded (nullable columns; a no-op when they already exist, e.g. a
fresh model-driven baseline). Backfill (PostgreSQL, existing DBs) attributes past
rows from the api_keys still present: interactions store the prefixed principal id
("key:<key_id>"), so the join strips the prefix. Rows whose key was already
deleted stay NULL and are simply excluded from tenant-scoped queries.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0019_proxy_interactions_tenant"
down_revision: str | None = "0018_drop_legacy_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE   = "proxy_interactions"
_COLUMNS = ("tenant_id", "dept_id", "app_id")
_INDEX   = "ix_proxy_int_tenant_time"


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        return

    existing_cols    = {c["name"] for c in inspector.get_columns(_TABLE)}
    existing_indexes = {i["name"] for i in inspector.get_indexes(_TABLE)}

    for col in _COLUMNS:
        if col not in existing_cols:
            op.add_column(_TABLE, sa.Column(col, postgresql.UUID(as_uuid=True), nullable=True))
    if _INDEX not in existing_indexes:
        op.create_index(_INDEX, _TABLE, ["tenant_id", "created_at"])

    # Backfill from api_keys still present (PostgreSQL only).
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            UPDATE proxy_interactions pi
            SET tenant_id = ak.tenant_id,
                dept_id   = ak.dept_id,
                app_id    = ak.app_id
            FROM api_keys ak
            WHERE pi.tenant_id IS NULL
              AND pi.key_id = 'key:' || ak.key_id
            """
        )


def downgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        return
    existing_indexes = {i["name"] for i in inspector.get_indexes(_TABLE)}
    if _INDEX in existing_indexes:
        op.drop_index(_INDEX, table_name=_TABLE)
    existing_cols = {c["name"] for c in inspector.get_columns(_TABLE)}
    for col in _COLUMNS:
        if col in existing_cols:
            op.drop_column(_TABLE, col)
