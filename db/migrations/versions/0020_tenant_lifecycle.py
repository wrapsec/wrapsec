# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""tenant lifecycle: add status/suspended_at/plan, drop is_active/global_policy

Revision ID: 0020_tenant_lifecycle
Revises: 0019_proxy_interactions_tenant
Create Date: 2026-08-14

Tenant lifecycle (D4) + remove dead global_policy (M3). status becomes the
authoritative lifecycle field; suspended_at records the last suspension; plan is
an opaque column. The old is_active flag and the never-resolved global_policy blob
are dropped.

Guarded/idempotent. On a fresh model-driven baseline the new columns already exist
and is_active/global_policy never did, so every step is a clean no-op. On an
existing database status is backfilled from is_active before the drop.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_tenant_lifecycle"
down_revision: str | None = "0019_proxy_interactions_tenant"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "tenants"


def upgrade() -> None:
    bind      = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        return

    cols = {c["name"] for c in inspector.get_columns(_TABLE)}

    if "status" not in cols:
        op.add_column(_TABLE, sa.Column("status", sa.String(16), nullable=False,
                                        server_default="active"))
    if "suspended_at" not in cols:
        op.add_column(_TABLE, sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True))
    if "plan" not in cols:
        op.add_column(_TABLE, sa.Column("plan", sa.String(50), nullable=True))

    # Backfill status from the legacy flag, then drop the legacy columns.
    if "is_active" in cols:
        op.execute(
            "UPDATE tenants SET status = CASE WHEN is_active THEN 'active' ELSE 'suspended' END"
        )
        op.drop_column(_TABLE, "is_active")
    if "global_policy" in cols:
        op.drop_column(_TABLE, "global_policy")


def downgrade() -> None:
    # One-way: is_active is superseded by status and global_policy was never used.
    pass
