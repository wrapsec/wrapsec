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
    docker exec wrapsec_api python scripts/seed_e2e_user.py

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


async def seed() -> int:
    from db.repositories.membership import MembershipRepository
    from db.repositories.tenant import TenantRepository
    from db.repositories.user import UserRepository
    from db.session import AsyncSessionFactory
    from services.auth.password import (
        hash_password,
        normalize_email,
        validate_password_strength,
    )

    validate_password_strength(E2E_PASSWORD)
    email = normalize_email(E2E_EMAIL)

    async with AsyncSessionFactory() as db:
        tenant = await TenantRepository(db).get_bootstrap_default()
        if not tenant:
            print("seed_e2e_user: no default tenant found", file=sys.stderr)
            return 1

        user_repo = UserRepository(db)
        existing  = await user_repo.get_by_email(email)

        if existing is None:
            user = await user_repo.create({
                "email":                 email,
                "password_hash":         hash_password(E2E_PASSWORD),
                "force_password_change": False,
            })
            await user_repo.flush()
            action = "created"
        else:
            # Reset password + clear any force-change / disabled state so login is
            # deterministic. Never touches other users.
            await user_repo.update(existing.id, {
                "password_hash":         hash_password(E2E_PASSWORD),
                "force_password_change": False,
                "is_active":             True,
            })
            user   = existing
            action = "reset"

        # Ensure an ADMIN membership in the default tenant (upsert is idempotent).
        await MembershipRepository(db).upsert_for_user(
            user_id=user.id, tenant_id=tenant.id, role="ADMIN", dept_id=None,
        )
        await db.commit()

    print(f"seed_e2e_user: {action} {email} (ADMIN, tenant={tenant.slug})")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("TESTING", "false")
    raise SystemExit(asyncio.run(seed()))
