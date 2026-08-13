# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""unique (tenant_id, slug) among active departments and applications

Revision ID: 0012_dept_app_slug_unique
Revises: 0011_audit_input_source
Create Date: 2026-08-09

Department and application slugs are stable per-tenant identifiers used in policy
resolution, but they had no uniqueness guarantee (only a plain tenant_id index),
so two resources in the same tenant could share a slug. This adds a partial
UNIQUE index on (tenant_id, slug) restricted to ACTIVE rows, so:
  - two active departments (or applications) in a tenant cannot share a slug;
  - a slug frees up once its resource is deactivated (soft-deleted).

Assumes no existing ACTIVE duplicate (tenant_id, slug) rows (true on the current
demo/sample data). Idempotent: guarded by an index-existence check so a re-run or
a fresh install whose model-driven baseline already has the index is a no-op.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_dept_app_slug_unique"
down_revision: str | None = "0011_audit_input_source"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_INDEXES = [
    ("departments",  "uq_dept_tenant_slug_active"),
    ("applications", "uq_app_tenant_slug_active"),
]


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)
    tables    = set(inspector.get_table_names())

    for table, name in _INDEXES:
        if table not in tables:
            continue
        existing = {ix["name"] for ix in inspector.get_indexes(table)}
        if name not in existing:
            op.create_index(
                name, table, ["tenant_id", "slug"],
                unique=True, postgresql_where=sa.text("is_active"),
            )


def downgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)
    tables    = set(inspector.get_table_names())

    for table, name in _INDEXES:
        if table not in tables:
            continue
        existing = {ix["name"] for ix in inspector.get_indexes(table)}
        if name in existing:
            op.drop_index(name, table_name=table)
