# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Seed (or reset) a dedicated E2E admin account for Playwright end-to-end tests.

Idempotent: creates e2e-admin@wrapsec.test if absent, otherwise resets its
password / flags. Gives it an ADMIN membership in the default tenant with
force_password_change disabled so the login journey lands straight on the
dashboard. This account is isolated from real dev users and is the ONLY identity
the E2E suite authenticates with.

Run inside the api container (has the app + DB access):
    docker compose -f infrastructure/docker/docker-compose.yml exec -T api \
        python scripts/seed_e2e_user.py

Credentials are overridable via env (E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD) so CI
can inject its own; defaults below are for the local stack.
"""
import asyncio
import os
import sys

# Allow `python scripts/seed_e2e_user.py` from anywhere: put the repo root on the
# path (running a script file only adds the script's own dir).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# NOTE: the domain must pass EmailStr -- RFC 2606 special-use TLDs (.test,
# .example, .invalid, .localhost) are rejected with 422, so use a real TLD.
E2E_EMAIL    = os.getenv("E2E_ADMIN_EMAIL", "e2e-admin@wrapsec-e2e.com")
E2E_PASSWORD = os.getenv("E2E_ADMIN_PASSWORD", "E2eAdmin!Pass123")


# Second identity: a VIEWER, for the "unauthorized -> denied" E2E journey.
E2E_VIEWER_EMAIL = os.getenv("E2E_VIEWER_EMAIL", "e2e-viewer@wrapsec-e2e.com")


async def _seed_user(db, email, password, role, dept_id):
    """Create or reset a user + ensure its (role, dept) membership. Idempotent."""
    from db.repositories.membership import MembershipRepository
    from db.repositories.user import UserRepository

    user_repo = UserRepository(db)
    existing  = await user_repo.get_by_email(email)
    if existing is None:
        user = await user_repo.create({
            "email":                 email,
            "password_hash":         password,
            "force_password_change": False,
        })
        await user_repo.flush()
        action = "created"
    else:
        await user_repo.update(existing.id, {
            "password_hash":         password,
            "force_password_change": False,
            "is_active":             True,
        })
        user   = existing
        action = "reset"

    await MembershipRepository(db).upsert_for_user(
        user_id=user.id, tenant_id=dept_id[0], role=role, dept_id=dept_id[1],
    )
    return action


async def seed() -> int:
    from db.repositories.department import DepartmentRepository
    from db.repositories.tenant import TenantRepository
    from db.session import AsyncSessionFactory
    from services.auth.password import (
        hash_password,
        normalize_email,
        validate_password_strength,
    )

    validate_password_strength(E2E_PASSWORD)
    admin_email  = normalize_email(E2E_EMAIL)
    viewer_email = normalize_email(E2E_VIEWER_EMAIL)
    pw_hash      = hash_password(E2E_PASSWORD)

    async with AsyncSessionFactory() as db:
        tenant = await TenantRepository(db).get_bootstrap_default()
        if not tenant:
            print("seed_e2e_user: no default tenant found", file=sys.stderr)
            return 1

        # The VIEWER requires a dept_id (ck_users_dept_required). Provision a
        # dedicated e2e department rather than relying on the dev DB's seed state
        # (idempotent; never touches real dev departments).
        dept_repo = DepartmentRepository(db)
        existing  = await dept_repo.list_by_tenant(tenant.id)
        dept      = next((d for d in existing if d.slug == "e2e"), None)
        if dept is None:
            dept = await dept_repo.create({"tenant_id": tenant.id, "slug": "e2e", "name": "E2E"})
            await dept_repo.flush()
        dept_id = str(dept.id)

        a = await _seed_user(db, admin_email,  pw_hash, "ADMIN",  (tenant.id, None))
        v = await _seed_user(db, viewer_email, pw_hash, "VIEWER", (tenant.id, dept_id))
        await db.commit()

    print(f"seed_e2e_user: {a} {admin_email} (ADMIN); {v} {viewer_email} (VIEWER)")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("TESTING", "false")
    raise SystemExit(asyncio.run(seed()))
