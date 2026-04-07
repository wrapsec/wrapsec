import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.settings import get_settings
from errors.exceptions import WrapSecError
from errors.handlers import wrapsec_exception_handler, unhandled_exception_handler
from api.v1.router import router as v1_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print(f"Starting {settings.app_name} v{settings.app_version}")
    print(f"Environment: {settings.environment}")
    yield
    # Shutdown
    print(f"Shutting down {settings.app_name}")


app = FastAPI(
    title       = settings.app_name,
    version     = settings.app_version,
    description = "AI Security Gateway for Intelligent Applications",
    docs_url    = "/docs" if settings.environment != "production" else None,
    redoc_url   = "/redoc" if settings.environment != "production" else None,
    lifespan    = lifespan,
)

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
app.add_exception_handler(Exception, unhandled_exception_handler)

# ── Request timing middleware ─────────────────────────────────
@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = (time.perf_counter() - start) * 1000
    response.headers["X-Response-Time-Ms"] = str(round(elapsed, 2))
    return response

# ── Routers ───────────────────────────────────────────────────
app.include_router(v1_router)