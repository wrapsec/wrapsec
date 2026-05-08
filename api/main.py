# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import time
from contextlib import asynccontextmanager
from observability.logging import setup_logging
from observability.metrics import get_metrics
import hmac
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi import Response

from config.settings import get_settings
from errors.exceptions import WrapSecError
from errors.handlers import wrapsec_exception_handler, unhandled_exception_handler, validation_exception_handler
from fastapi.exceptions import RequestValidationError
from api.v1.router import router as v1_router
from api.v1.middleware.trace import TraceMiddleware
from api.v1.middleware.logging import LoggingMiddleware
from api.v1.middleware.auth import AuthMiddleware
from api.v1.middleware.rate_limit import RateLimitMiddleware
from api.v1.middleware.idempotency import IdempotencyMiddleware

setup_logging()


async def seed_default_tenant() -> None:
    """
    Ensures a default tenant exists. Required for fresh Docker deployments
    before the /setup page or bootstrap_admin can create users.
    Idempotent — skips silently if the tenant already exists.
    """
    import logging
    logger = logging.getLogger("wrapsec.seed")
    try:
        from db.session import AsyncSessionFactory
        from db.repositories.tenant import TenantRepository
        from db.models import TenantModel
        async with AsyncSessionFactory() as db:
            repo   = TenantRepository(db)
            tenant = await repo.get_default()
            if not tenant:
                db.add(TenantModel(
                    slug          = "default",
                    name          = "Default",
                    description   = "Default tenant",
                    global_policy = {},
                    is_active     = True,
                ))
                await db.commit()
                logger.info("seed default tenant created")
    except Exception as e:
        logger.error("seed default tenant failed: %s", e)


async def bootstrap_admin() -> None:
    """
    Creates the first admin user if ADMIN_EMAIL and ADMIN_PASSWORD are set in
    .env AND the users table is empty. Skips silently if either var is unset —
    in that case the dashboard /setup page handles first-user creation.

    Runs on every startup — skips silently if users already exist.
    Non-fatal — system starts even if bootstrap fails.
    """
    import logging

    logger = logging.getLogger("wrapsec.bootstrap")

    try:
        _settings = get_settings()

        # Skip if env vars not configured — /setup page handles first-user creation
        if not _settings.admin_email or not _settings.admin_password:
            logger.info("bootstrap skipped — ADMIN_EMAIL/ADMIN_PASSWORD not set; "
                        "use the dashboard /setup page to create the first admin user")
            return

        from db.session import AsyncSessionFactory
        from db.repositories.tenant import TenantRepository
        from db.repositories.user import UserRepository
        from services.auth.password import (
            hash_password, normalize_email, validate_password_strength,
        )

        async with AsyncSessionFactory() as db:
            tenant = await TenantRepository(db).get_default()
            if not tenant:
                logger.error("bootstrap no_default_tenant — skipping admin creation")
                return

            user_repo = UserRepository(db)
            if await user_repo.count_by_tenant(tenant.id) > 0:
                return  # Users already exist — skip silently

            email = normalize_email(_settings.admin_email)

            try:
                validate_password_strength(_settings.admin_password)
            except ValueError as e:
                logger.error("bootstrap admin_password_too_weak: %s — skipping", e)
                return

            await user_repo.create({
                "tenant_id":             tenant.id,
                "dept_id":               None,
                "email":                 email,
                "password_hash":         hash_password(_settings.admin_password),
                "role":                  "ADMIN",
                "force_password_change": True,
            })
            await db.commit()

            logger.info("bootstrap admin_created email=%s force_password_change=True", email)

    except Exception as e:
        logger.error("bootstrap failed: %s", e)
        # Non-fatal — system continues to start


@asynccontextmanager
async def lifespan(app: FastAPI):
    import os
    if os.getenv("TESTING") != "true":
        from db.session import create_tables, dispose_engine
        from cache.redis_client import ping, close
        from workers.queue import start_scheduler, stop_scheduler
        _settings = get_settings()
        await create_tables()
        redis_ok = await ping()
        await start_scheduler()
        await seed_default_tenant()      # ensure default tenant exists (fresh deploy)
        await bootstrap_admin()          # create first admin if users table is empty
        print(f"Starting {_settings.app_name} v{_settings.app_version}")
        print(f"Environment: {_settings.environment}")
        print(f"Redis: {'connected' if redis_ok else 'unavailable'}")
        yield
        await stop_scheduler()
        await close()
        await dispose_engine()
        print(f"Shutting down {_settings.app_name}")
    else:
        yield


_startup_settings = get_settings()

app = FastAPI(
    title       = _startup_settings.app_name,
    version     = _startup_settings.app_version,
    description = "AI Security Gateway for Intelligent Applications",
    docs_url    = "/docs" if _startup_settings.environment != "production" else None,
    redoc_url   = "/redoc" if _startup_settings.environment != "production" else None,
    lifespan    = lifespan,
)

# ── Middleware — order matters, outermost registered last ─────
# Request flow: Trace → RateLimit → Auth → Idempotency → Logging → endpoint
# Idempotency must be after Auth so key_id is available in request.state
app.add_middleware(LoggingMiddleware)
app.add_middleware(IdempotencyMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(TraceMiddleware)

# ── CORS ──────────────────────────────────────────────────────
# RFC 6454: allow_credentials=True with allow_origins=["*"] is invalid —
# browsers reject this combination. Credentials are only sent when origins
# are explicitly listed via CORS_ALLOWED_ORIGINS in .env.
_cors_origins     = _startup_settings.cors_allowed_origins
_cors_credentials = bool(_cors_origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins     = _cors_origins,
    allow_credentials = _cors_credentials,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Exception handlers ────────────────────────────────────────
app.add_exception_handler(WrapSecError, wrapsec_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

# ── Routers ───────────────────────────────────────────────────
app.include_router(v1_router)

# ── Metrics endpoint ──────────────────────────────────────────
# Requires Bearer token: METRICS_TOKEN if set, otherwise ADMIN_API_KEY.
@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    _s          = get_settings()
    expected    = _s.metrics_token or _s.admin_api_key
    auth_header = request.headers.get("authorization", "")
    token       = auth_header.removeprefix("Bearer ").strip()
    if not token or not hmac.compare_digest(token, expected):
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    data, content_type = get_metrics()
    return Response(content=data, media_type=content_type)
