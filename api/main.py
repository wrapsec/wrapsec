import time
from contextlib import asynccontextmanager
from observability.logging import setup_logging
from observability.metrics import get_metrics
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

settings = get_settings()

setup_logging()


async def bootstrap_admin() -> None:
    """
    Creates the first admin user if the users table is empty for the default tenant.
    Runs on every startup — skips silently if users already exist.
    Non-fatal — system starts even if bootstrap fails.

    Sets force_password_change = True — enforced at middleware level.
    Admin must change password on first login before accessing anything.

    Production safety: logs ERROR + prints to stderr if default password detected.
    Change ADMIN_PASSWORD in .env before first production startup.
    """
    import logging
    import sys

    logger = logging.getLogger("wrapsec.bootstrap")

    try:
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

            email = normalize_email(settings.admin_email)

            try:
                validate_password_strength(settings.admin_password)
            except ValueError as e:
                logger.error("bootstrap admin_password_too_weak: %s — skipping", e)
                return

            await user_repo.create({
                "tenant_id":             tenant.id,
                "dept_id":               None,
                "email":                 email,
                "password_hash":         hash_password(settings.admin_password),
                "role":                  "ADMIN",
                "force_password_change": True,
            })
            await db.commit()

            # Production safety check — warn loudly if default password unchanged
            DEFAULT_PASSWORD = "ChangeMe!OnFirstLogin"
            if (settings.environment == "production"
                    and settings.admin_password == DEFAULT_PASSWORD):
                warning_msg = (
                    "\n"
                    "╔══════════════════════════════════════════════════════════════╗\n"
                    "║  ⚠  WRAPSEC SECURITY WARNING                                 ║\n"
                    "║  Default ADMIN_PASSWORD detected in production environment.  ║\n"
                    "║  Change ADMIN_PASSWORD in .env IMMEDIATELY.                  ║\n"
                    "║  Do not allow any user to log in until this is changed.      ║\n"
                    "╚══════════════════════════════════════════════════════════════╝\n"
                )
                print(warning_msg, file=sys.stderr, flush=True)
                logger.error(
                    "bootstrap SECURITY_RISK default_admin_password_in_production "
                    "— change ADMIN_PASSWORD in .env immediately"
                )

            logger.info("bootstrap admin_created email=%s", email)
            logger.warning(
                "bootstrap CHANGE_PASSWORD — force_password_change=True is set. "
                "Admin must change password on first login."
            )

    except Exception as e:
        logger.error("bootstrap failed: %s", e)
        # Non-fatal — system continues to start


@asynccontextmanager
async def lifespan(app: FastAPI):
    import os
    if os.getenv("TESTING") != "true":
        from db.session import create_tables
        from cache.redis_client import ping, close
        from workers.queue import start_scheduler, stop_scheduler
        await create_tables()
        redis_ok = await ping()
        await start_scheduler()
        await bootstrap_admin()          # create first admin if users table is empty
        print(f"Starting {settings.app_name} v{settings.app_version}")
        print(f"Environment: {settings.environment}")
        print(f"Redis: {'connected' if redis_ok else 'unavailable'}")
        yield
        await stop_scheduler()
        await close()
        print(f"Shutting down {settings.app_name}")
    else:
        yield


app = FastAPI(
    title       = settings.app_name,
    version     = settings.app_version,
    description = "AI Security Gateway for Intelligent Applications",
    docs_url    = "/docs" if settings.environment != "production" else None,
    redoc_url   = "/redoc" if settings.environment != "production" else None,
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
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"] if settings.environment == "development" else [],
    allow_credentials = True,
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
@app.get("/metrics", include_in_schema=False)
async def metrics():
    data, content_type = get_metrics()
    return Response(content=data, media_type=content_type)
