# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""admit AUDITOR into the users.role check constraints

Revision ID: 0005_add_auditor_role
Revises: 0004_audit_immutable_trigger
Create Date: 2026-07-28

Adds AUDITOR as a fourth accepted value for `users.role` and reworks the
role/dept coupling so AUDITOR can be either tenant-wide (dept_id NULL) or
department-scoped (dept_id set).

Rationale for the flexible dept coupling: enterprise reference roles map
this way. AWS SecurityAudit can be attached to an account root or an OU,
Azure Security Reader can be assigned at subscription or resource-group
scope, and GitHub's Security manager can be team-scoped or org-wide.
Pinning AUDITOR to NULL would force compliance leads at large tenants to
share a single tenant-wide login; pinning it to NOT NULL would break the
tenant-wide auditor use-case that GRC teams actually ask for.

Two constraints are rewritten (drop + add, not alter -- Postgres does not
support ALTER CONSTRAINT for CHECK expressions):

  ck_users_role
    Old: role IN ('ADMIN', 'DEVELOPER', 'VIEWER')
    New: role IN ('ADMIN', 'DEVELOPER', 'VIEWER', 'AUDITOR')

  ck_users_dept_required_v2
    Old: (role = 'ADMIN'  AND dept_id IS NULL)
      OR (role <> 'ADMIN' AND dept_id IS NOT NULL)
    New: (role = 'ADMIN'   AND dept_id IS NULL)
      OR (role = 'AUDITOR')
      OR (role IN ('DEVELOPER', 'VIEWER') AND dept_id IS NOT NULL)

Idempotent + dialect-aware:

  * Postgres upgraders (v1.2.0 mid-release): DROP IF EXISTS + ADD is a
    single tx, no rewrite of the users table.
  * Fresh installs (any dialect): 0001_baseline's create_all pulls the
    CURRENT models.py, which already carries the new constraint text, so
    this migration finds the constraint already correct and its DROP just
    strips it before we re-add the identical body -- effectively a no-op.
  * SQLite upgraders (dev sandboxes): SQLite CHECK constraints are
    unnamed at the storage layer; a `DROP CONSTRAINT` is a parse error.
    The `batch_alter_table` path rebuilds the table via copy, which is
    the only supported SQLite mechanism for CHECK edits. We only take
    that path on SQLite.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "0005_add_auditor_role"
down_revision: Union[str, None] = "0004_audit_immutable_trigger"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_NEW_ROLE_CHECK = "role IN ('ADMIN', 'DEVELOPER', 'VIEWER', 'AUDITOR')"

_NEW_DEPT_CHECK = (
    "(role = 'ADMIN' AND dept_id IS NULL) OR "
    "(role = 'AUDITOR') OR "
    "(role IN ('DEVELOPER', 'VIEWER') AND dept_id IS NOT NULL)"
)

_OLD_ROLE_CHECK = "role IN ('ADMIN', 'DEVELOPER', 'VIEWER')"

_OLD_DEPT_CHECK = (
    "(role = 'ADMIN' AND dept_id IS NULL) OR "
    "(role != 'ADMIN' AND dept_id IS NOT NULL)"
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_role;")
        op.execute(
            f"ALTER TABLE users ADD CONSTRAINT ck_users_role CHECK ({_NEW_ROLE_CHECK});"
        )
        op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_dept_required_v2;")
        op.execute(
            "ALTER TABLE users ADD CONSTRAINT ck_users_dept_required_v2 CHECK ("
            f"{_NEW_DEPT_CHECK});"
        )
        return

    # SQLite path: table rebuild via batch mode. CHECK constraint names
    # in SQLite are stored inline in the CREATE TABLE text, so alembic
    # emits a new-table + copy-rows + rename dance for us.
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_role",             type_="check")
        batch_op.drop_constraint("ck_users_dept_required_v2", type_="check")
        batch_op.create_check_constraint("ck_users_role",             _NEW_ROLE_CHECK)
        batch_op.create_check_constraint("ck_users_dept_required_v2", _NEW_DEPT_CHECK)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_role;")
        op.execute(
            f"ALTER TABLE users ADD CONSTRAINT ck_users_role CHECK ({_OLD_ROLE_CHECK});"
        )
        op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_dept_required_v2;")
        op.execute(
            "ALTER TABLE users ADD CONSTRAINT ck_users_dept_required_v2 CHECK ("
            f"{_OLD_DEPT_CHECK});"
        )
        return

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_role",             type_="check")
        batch_op.drop_constraint("ck_users_dept_required_v2", type_="check")
        batch_op.create_check_constraint("ck_users_role",             _OLD_ROLE_CHECK)
        batch_op.create_check_constraint("ck_users_dept_required_v2", _OLD_DEPT_CHECK)
