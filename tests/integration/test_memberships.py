# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
MembershipModel / MembershipRepository and the 0015 backfill (identity D2 Option B,
expand phase C1a).

These require real PostgreSQL (the check constraints, the unique constraint, and
the backfill SQL are exercised against the actual schema, not SQLite). They scope
themselves by random UUIDs and clean up, because users/tenants/memberships are not
truncated between tests.
"""
import uuid

import pytest
import sqlalchemy as sa

from db.models import DepartmentModel, MembershipModel, TenantModel, UserModel
from db.repositories.membership import MembershipRepository


async def _seed_tenant_dept_user(session, *, role="DEVELOPER", with_dept=True):
    tenant_id = uuid.uuid4()
    dept_id   = uuid.uuid4() if with_dept else None
    user_id   = uuid.uuid4()

    session.add(TenantModel(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", name="T"))
    await session.flush()  # tenant must exist before dept/user FKs resolve
    if with_dept:
        session.add(DepartmentModel(id=dept_id, tenant_id=tenant_id,
                                    slug=f"d-{dept_id.hex[:8]}", name="D"))
        await session.flush()
    session.add(UserModel(
        id=user_id, tenant_id=tenant_id, dept_id=dept_id,
        email=f"{user_id.hex[:8]}@example.com", password_hash="x", role=role,
    ))
    await session.flush()
    return tenant_id, dept_id, user_id


async def _cleanup(session, tenant_id):
    await session.execute(sa.delete(MembershipModel).where(MembershipModel.tenant_id == tenant_id))
    await session.execute(sa.delete(UserModel).where(UserModel.tenant_id == tenant_id))
    await session.execute(sa.delete(DepartmentModel).where(DepartmentModel.tenant_id == tenant_id))
    await session.execute(sa.delete(TenantModel).where(TenantModel.id == tenant_id))
    await session.commit()


@pytest.mark.asyncio
async def test_create_admin_membership_without_dept(pg_db):
    tenant_id, _, user_id = await _seed_tenant_dept_user(pg_db, role="ADMIN", with_dept=False)
    try:
        repo = MembershipRepository(pg_db)
        m = await repo.create({"user_id": user_id, "tenant_id": tenant_id, "role": "ADMIN"})
        await pg_db.flush()
        assert m.role == "ADMIN" and m.dept_id is None
    finally:
        await _cleanup(pg_db, tenant_id)


@pytest.mark.asyncio
async def test_developer_membership_requires_dept(pg_db):
    tenant_id, _, user_id = await _seed_tenant_dept_user(pg_db, role="ADMIN", with_dept=False)
    try:
        repo = MembershipRepository(pg_db)
        with pytest.raises(ValueError, match="dept_id is required"):
            await repo.create({"user_id": user_id, "tenant_id": tenant_id, "role": "DEVELOPER"})
    finally:
        await _cleanup(pg_db, tenant_id)


@pytest.mark.asyncio
async def test_membership_rejects_cross_tenant_dept(pg_db):
    tenant_id, dept_id, user_id = await _seed_tenant_dept_user(pg_db)
    other_tenant = uuid.uuid4()
    pg_db.add(TenantModel(id=other_tenant, slug=f"o-{other_tenant.hex[:8]}", name="O"))
    await pg_db.flush()
    try:
        repo = MembershipRepository(pg_db)
        # dept belongs to tenant_id, not other_tenant -> cross-tenant linkage blocked
        with pytest.raises(ValueError, match="does not belong to tenant"):
            await repo.create({"user_id": user_id, "tenant_id": other_tenant,
                               "role": "DEVELOPER", "dept_id": dept_id})
    finally:
        await _cleanup(pg_db, tenant_id)
        await _cleanup(pg_db, other_tenant)


@pytest.mark.asyncio
async def test_unique_membership_per_user_tenant(pg_db):
    tenant_id, dept_id, user_id = await _seed_tenant_dept_user(pg_db)
    try:
        repo = MembershipRepository(pg_db)
        await repo.create({"user_id": user_id, "tenant_id": tenant_id,
                           "role": "DEVELOPER", "dept_id": dept_id})
        await pg_db.flush()
        with pytest.raises(sa.exc.IntegrityError):
            await repo.create({"user_id": user_id, "tenant_id": tenant_id,
                               "role": "VIEWER", "dept_id": dept_id})
            await pg_db.flush()
    finally:
        await pg_db.rollback()
        await _cleanup(pg_db, tenant_id)


@pytest.mark.asyncio
async def test_backfill_maps_user_to_membership_idempotently(pg_db):
    """The 0015 backfill INSERT: one membership per user, re-run creates no dup."""
    tenant_id, dept_id, user_id = await _seed_tenant_dept_user(pg_db, role="DEVELOPER")
    # Mirrors the INSERT in db/migrations/versions/0015_memberships.py. Scoped to
    # this test's user so it never touches unrelated rows in a shared PG.
    backfill = sa.text("""
        INSERT INTO memberships (id, user_id, tenant_id, dept_id, role, created_at)
        SELECT gen_random_uuid(), u.id, u.tenant_id, u.dept_id, u.role, u.created_at
        FROM users u
        WHERE u.id = :uid AND NOT EXISTS (
            SELECT 1 FROM memberships m
            WHERE m.user_id = u.id AND m.tenant_id = u.tenant_id
        )
    """)
    try:
        await pg_db.execute(backfill, {"uid": user_id})
        await pg_db.execute(backfill, {"uid": user_id})  # idempotent re-run
        await pg_db.commit()

        rows = (await pg_db.execute(
            sa.select(MembershipModel).where(MembershipModel.user_id == user_id)
        )).scalars().all()
        assert len(rows) == 1
        assert rows[0].tenant_id == tenant_id
        assert rows[0].dept_id   == dept_id
        assert rows[0].role      == "DEVELOPER"
    finally:
        await _cleanup(pg_db, tenant_id)
