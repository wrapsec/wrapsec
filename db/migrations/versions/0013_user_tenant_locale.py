# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add nullable locale column to users and tenants

Revision ID: 0013_user_tenant_locale
Revises: 0012_dept_app_slug_unique
Create Date: 2026-08-11

Locale-preference infrastructure (Phase 2). Adds a nullable BCP-47 `locale`
column to users and tenants. NULL means "inherit": a user with no locale falls
back to the tenant, then the system default, then English. The value is
validated against the supported-locales allowlist before use; the column merely
stores the preference.

Nullable with no default, so the ADD is non-locking and safe on a live table
(existing rows stay NULL = inherit). Idempotent: guarded by a column-existence
check, so a re-run or a fresh model-driven baseline that already has the column
is a no-op.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_user_tenant_locale"
down_revision: str | None = "0012_dept_app_slug_unique"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TABLES = ("users", "tenants")
_COLUMN = "locale"


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    for table in _TABLES:
        if table not in inspector.get_table_names():
            continue
        existing = {col["name"] for col in inspector.get_columns(table)}
        if _COLUMN not in existing:
            op.add_column(table, sa.Column(_COLUMN, sa.String(35), nullable=True))


def downgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)

    for table in _TABLES:
        if table not in inspector.get_table_names():
            continue
        existing = {col["name"] for col in inspector.get_columns(table)}
        if _COLUMN in existing:
            op.drop_column(table, _COLUMN)
