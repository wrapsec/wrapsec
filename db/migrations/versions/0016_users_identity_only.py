# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""drop tenant_id/dept_id/role from users (identity contract phase)

Revision ID: 0016_users_identity_only
Revises: 0015_memberships
Create Date: 2026-08-14

Identity model D2 Option B, contract phase (C1c). Tenant, role, and departmental
scope now live on memberships (populated by the 0015 backfill), so the mirrored
user columns are removed: users becomes pure identity.

Drops, if present (guarded so a fresh model-driven baseline that never had these
columns is a clean no-op, and re-running is safe):
  - check constraints ck_users_role, ck_users_dept_required_v2
  - indexes ix_users_tenant, ix_users_dept, ix_users_role, ix_users_role_active
  - columns role, dept_id, tenant_id (dropping the columns also drops their FKs)

No downgrade data path: the dropped values already exist on memberships.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_users_identity_only"
down_revision: str | None = "0015_memberships"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONSTRAINTS = ("ck_users_role", "ck_users_dept_required_v2")
_INDEXES     = ("ix_users_tenant", "ix_users_dept", "ix_users_role", "ix_users_role_active")
_COLUMNS     = ("role", "dept_id", "tenant_id")


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)
    if "users" not in inspector.get_table_names():
        return

    existing_checks  = {c["name"] for c in inspector.get_check_constraints("users")}
    existing_indexes = {i["name"] for i in inspector.get_indexes("users")}
    existing_columns = {c["name"] for c in inspector.get_columns("users")}

    for name in _CONSTRAINTS:
        if name in existing_checks:
            op.drop_constraint(name, "users", type_="check")
    for name in _INDEXES:
        if name in existing_indexes:
            op.drop_index(name, table_name="users")
    for name in _COLUMNS:
        if name in existing_columns:
            op.drop_column("users", name)


def downgrade() -> None:
    # One-way: role/dept/tenant now live on memberships; there is no lossless
    # reconstruction of the per-user columns, so downgrade is intentionally a no-op.
    pass
