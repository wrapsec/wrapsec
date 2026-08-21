# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""auth events: identify the credential a refusal applies to

Revision ID: 0023_auth_event_key_id
Revises: 0022_api_key_ip_allowlist
Create Date: 2026-08-21

The table was built for sign-ins, so a row identifies a user. A machine
credential refused because it was presented from an address its owner did not
permit has no user, and without this column such a row says only that some
credential in the tenant was refused -- not which one. That is the first
question anyone asks during an incident, and the difference between revoking
one key and auditing all of them.

Stores the bare credential id as it appears in `api_keys.key_id`, NOT the
prefixed form the request state carries, so a reader can join the two directly.
This table has no prior convention to honour.

Indexed because the queries that matter are per credential: what was refused
for this key, and from where.

Guarded/idempotent. On a fresh model-driven baseline the column already exists
and the step is a no-op.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023_auth_event_key_id"
down_revision: str | None = "0022_api_key_ip_allowlist"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE  = "auth_events"
_COLUMN = "key_id"
_INDEX  = "ix_auth_events_key_id"


def _inspector():
    return sa.inspect(op.get_bind())


def _existing_columns() -> set[str]:
    inspector = _inspector()
    if _TABLE not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(_TABLE)}


def _existing_indexes() -> set[str]:
    inspector = _inspector()
    if _TABLE not in inspector.get_table_names():
        return set()
    return {
        str(index["name"])
        for index in inspector.get_indexes(_TABLE)
        if index.get("name")
    }


def upgrade() -> None:
    present = _existing_columns()
    if not present:
        return  # table absent on a throwaway database; nothing to alter
    if _COLUMN not in present:
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.String(50), nullable=True))
    if _INDEX not in _existing_indexes():
        op.create_index(_INDEX, _TABLE, [_COLUMN])


def downgrade() -> None:
    if _INDEX in _existing_indexes():
        op.drop_index(_INDEX, table_name=_TABLE)
    if _COLUMN in _existing_columns():
        op.drop_column(_TABLE, _COLUMN)
