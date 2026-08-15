# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""add memberships table and backfill one membership per user

Revision ID: 0015_memberships
Revises: 0014_email_outbox
Create Date: 2026-08-14

Identity model D2 Option B, expand phase (C1a). Separates identity (users) from
membership (this table): a user's tenant_id + role + departmental scope move here
so one human can hold roles in multiple tenants. This migration is ADDITIVE --
users.tenant_id/dept_id/role are left in place and keep working until the later
contract-phase migration drops them.

Backfill: one membership per existing user, copying the user's current
tenant_id/dept_id/role. Guarded so it is a no-op when:
  - the memberships table already exists (fresh model-driven baseline via 0001
    create_all), in which case only the backfill runs; and
  - users.tenant_id no longer exists (a fresh database created AFTER the contract
    phase drops those columns) -- there is nothing to backfill, so skip cleanly.
Re-running is safe: the INSERT selects only users without an existing membership.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015_memberships"
down_revision: str | None = "0014_email_outbox"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "memberships"


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)
    tables    = set(inspector.get_table_names())

    if _TABLE not in tables:
        op.create_table(
            _TABLE,
            sa.Column("id",        postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("user_id",   postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("dept_id",   postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("role",      sa.String(50), nullable=False, server_default="DEVELOPER"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(["user_id"],   ["users.id"],       ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
            sa.ForeignKeyConstraint(["dept_id"],   ["departments.id"]),
            sa.UniqueConstraint("user_id", "tenant_id", name="uq_memberships_user_tenant"),
            sa.CheckConstraint(
                "role IN ('ADMIN', 'DEVELOPER', 'VIEWER', 'AUDITOR')",
                name="ck_memberships_role",
            ),
            sa.CheckConstraint(
                "(role = 'ADMIN' AND dept_id IS NULL) OR "
                "(role = 'AUDITOR') OR "
                "(role IN ('DEVELOPER', 'VIEWER') AND dept_id IS NOT NULL)",
                name="ck_memberships_dept_required",
            ),
        )
        op.create_index("ix_memberships_user",        _TABLE, ["user_id"])
        op.create_index("ix_memberships_tenant",      _TABLE, ["tenant_id"])
        op.create_index("ix_memberships_tenant_role", _TABLE, ["tenant_id", "role"])
        op.create_index("ix_memberships_dept",        _TABLE, ["dept_id"])

    # Backfill only when the legacy source columns still exist (pre-contract DB).
    # PostgreSQL only: uses gen_random_uuid(); the SQLite baseline-migration
    # smoke test starts from an empty DB (nothing to backfill) so skipping is
    # correct there. On a fresh PG the create_all baseline (0001) also starts
    # empty, so this is a zero-row no-op; on an existing dev/prod PG it populates.
    users_cols = {col["name"] for col in inspector.get_columns("users")}
    if bind.dialect.name == "postgresql" and {"tenant_id", "role"} <= users_cols:
        op.execute(
            """
            INSERT INTO memberships (id, user_id, tenant_id, dept_id, role, created_at)
            SELECT gen_random_uuid(), u.id, u.tenant_id, u.dept_id, u.role, u.created_at
            FROM users u
            WHERE NOT EXISTS (
                SELECT 1 FROM memberships m
                WHERE m.user_id = u.id AND m.tenant_id = u.tenant_id
            )
            """
        )


def downgrade() -> None:
    bind   = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if _TABLE in tables:
        op.drop_table(_TABLE)
