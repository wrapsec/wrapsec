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