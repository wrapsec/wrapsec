# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):

    # ── Application ───────────────────────────────────────────
    app_name:        str = "WrapSec"
    app_version:     str = "1.0.0"
    debug:           bool = False
    environment:     str = Field(default="development")  # development | staging | production

    # ── API ───────────────────────────────────────────────────
    api_host:        str = "0.0.0.0"
    api_port:        int = 8000
    api_workers:     int = 1
    # Explicit CORS origins for credential-bearing requests (dashboard).
    # Empty list disables credentialed CORS entirely.
    # Never use ["*"] with allow_credentials - browsers reject this.
    cors_allowed_origins: list[str] = Field(default_factory=list)

    # ── Security ──────────────────────────────────────────────
    secret_key:      str = Field(..., min_length=32)
    jwt_algorithm:   str = "HS256"
    admin_api_key:   str = Field(..., min_length=32)
    # Comma-separated list of trusted reverse proxy IPs or CIDRs.
    # x-forwarded-for is only trusted when the direct connection IP
    # matches one of these entries. Leave empty (default) to always
    # use the direct connection IP - safe when not behind a proxy.
    # Example: TRUSTED_PROXY_IPS=10.0.0.1,172.16.0.0/12
    trusted_proxy_ips: str = Field(default="")

    # ── JWT (dashboard auth) ──────────────────────────────────
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days:   int = 30

    # ── Bootstrap first admin (optional) ─────────────────────────────────────
    # If both are set, bootstrap creates the admin user automatically on first
    # startup (scripted / infrastructure-as-code deploys).
    # If either is unset (default), bootstrap is skipped - the dashboard /setup
    # page handles first-user creation interactively.
    admin_email:    str | None = Field(default=None)
    admin_password: str | None = Field(default=None)

    # ── Account lockout (Redis TTL) ───────────────────────────
    # After AUTH_MAX_FAILED_ATTEMPTS consecutive failures the account is locked
    # for AUTH_LOCKOUT_DURATION_SECONDS seconds (default 15 min).
    # Each failed attempt during lockout resets the TTL (extends lockout).
    auth_max_failed_attempts:    int = 5
    auth_lockout_duration_seconds: int = 900

    # ── Database ──────────────────────────────────────────────
    database_url:    str = Field(...)
    db_pool_size:    int = 10
    db_max_overflow: int = 20

    # ── Redis ─────────────────────────────────────────────────
    redis_url:       str = Field(default="redis://localhost:6379/0")
    redis_ttl:       int = 3600

    # ── Rate Limiting ─────────────────────────────────────────
    rate_limit_enabled:             bool = True
    rate_limit_per_minute:          int  = 60
    rate_limit_burst:               int  = 10
    admin_write_rate_limit:         int  = 20   # POST/PATCH on admin user endpoints
    audit_export_rate_limit:        int  = 5    # GET /audit/export

    # ── Audit log retention ────────────────────────────────────
    audit_retention_days:    int  = 30  # days to keep audit logs in DB

    # ── Detection Engine ──────────────────────────────────────
    default_detection_mode:    str   = "fast"
    default_execution_mode:    str   = "scan_only"
    block_threshold:           float = 0.7
    sanitize_threshold:        float = 0.4
    llm_trigger_threshold:     float = 0.2
    # Maximum input size for live keys (trial keys use trial_max_input_chars)
    max_input_chars:           int   = 8000
    # Output guardrail PII thresholds
    output_block_threshold:    float = 0.95
    output_sanitize_threshold: float = 0.01
    # H2: hard cap on regex-heavy detector execution to bound ReDoS blast
    # radius. Catastrophic-backtracking payloads that run past this cap are
    # aborted and treated as a detector failure - C1 fail-closed then forces
    # BLOCK. Default 2s is generous versus the ~5ms happy path.
    detector_timeout_seconds:  float = 2.0

    # ── LLM Provider ──────────────────────────────────────────
    llm_provider:             str = Field(default="ollama")  # ollama | openai | groq
    llm_model:                str = Field(default="llama3.2")
    llm_base_url:             str = Field(default="http://localhost:11434")
    openai_api_key:           str = Field(default="")
    groq_api_key:             str = Field(default="")
    llm_timeout:              int = 30
    llm_detection_max_tokens: int = 200

    # ── Idempotency ───────────────────────────────────────────
    idempotency_window_secs: int = 60

    # ── Observability ─────────────────────────────────────────
    log_level:               str       = "INFO"
    log_format:              str       = "json"
    prometheus_enabled:      bool      = True
    prometheus_port:         int       = 9090
    # Bearer token for /metrics endpoint. If unset, falls back to admin_api_key.
    # Set METRICS_TOKEN in .env to use a dedicated scraping credential.
    metrics_token:           str | None = Field(default=None)

    # ── Background retention worker ───────────────────────────────────────────
    # APScheduler runs cleanup daily at the configured time (UTC)
    # Set RETENTION_WORKER_ENABLED=false to disable (use manual script instead)
    retention_worker_enabled: bool = True
    retention_worker_hour:    int  = 2   # 2 AM UTC
    retention_worker_minute:  int  = 0

    # ── Webhook circuit breaker ───────────────────────────────────────────────
    # Auto-disable a webhook endpoint after it has been continuously failing
    # for `hours` hours (default 120h / 5 days -- matches the industry
    # convention adopted by widely-used OSS webhook delivery platforms).
    # A background sweep runs every `sweep_minutes` minutes to flip disabled.
    # Set _ENABLED=false to keep the sweep off (useful for tests / dev).
    webhook_circuit_breaker_enabled:       bool = True
    webhook_circuit_breaker_hours:         int  = 120
    webhook_circuit_breaker_sweep_minutes: int  = 15

    # -- Webhook delivery --
    # Per-attempt HTTP timeout against a receiver, and the byte ceiling on the
    # receiver response body persisted to webhook_delivery_attempts (an
    # unbounded column would let one misbehaving receiver fill disk).
    webhook_delivery_timeout_seconds:    int = 10
    webhook_delivery_max_response_bytes: int = 2048

    # ── Trial key limits ──────────────────────────────────────────────────────
    # Applied only when api_keys.key_type = 'trial'
    # Production (live) keys are completely unaffected by these settings
    trial_rate_limit_per_minute: int   = 10     # vs 60 for live keys
    trial_max_input_chars:       int   = 500    # vs 8000 for live keys
    trial_proxy_enabled:         bool  = False  # proxy disabled for trial keys

    # ── Login rate limit ──────────────────────────────────────────────────────
    # IP-based limit on POST /v1/auth/login - stricter than the global 60/min.
    # Prevents distributed brute force across many email addresses from one IP.
    # Per-email lockout (AUTH_MAX_FAILED_ATTEMPTS) still applies independently.
    # Intentionally env-only - not dashboard-configurable (security control).
    login_rate_limit_per_minute: int   = 10

    # ── Debug mode limits ─────────────────────────────────────────────────────
    # debug=true exposes per-layer scores - a tighter separate limit prevents
    # model fingerprinting (probing to calibrate below-threshold attacks).
    # Applies only to admin keys; non-admin keys are blocked before this check.
    # Intentionally env-only - not dashboard-configurable (security control).
    debug_rate_limit_per_minute: int   = 10

    # -- Cookie security -------------------------------------------------------
    # Set COOKIE_SECURE=false only for local HTTP dev environments.
    # Must be True in all deployed environments (staging, production).
    cookie_secure: bool = True

    # Default Path for the refresh_token cookie. Direct clients (SDK, browser
    # extension) hit /v1/auth/* and need this default. A BFF (dashboard)
    # fronts the backend under a different prefix; it overrides per-request
    # via the X-Refresh-Cookie-Path header, gated on Origin allowlist. See
    # api/v1/endpoints/auth.py:_resolve_refresh_cookie_path.
    refresh_cookie_path: str = Field(default="/v1/auth")

    # -- Data storage ----------------------------------------------------------
    data_storage_mode:        str = Field(default="masked")
    # full   -- store input_raw and output_raw as-is (development)
    # masked -- run PII redactor before storing (production default)
    # none   -- store None for input_raw and output_raw (strict compliance)
    data_retention_days_proxy: int = 7

    class Config:
        env_file         = ".env"
        env_file_encoding = "utf-8"
        case_sensitive   = False
        extra            = "ignore"

    def validate_thresholds(self) -> None:
        if self.block_threshold <= self.sanitize_threshold:
            raise ValueError(
                f"block_threshold ({self.block_threshold}) must be greater "
                f"than sanitize_threshold ({self.sanitize_threshold})"
            )

    def validate_secrets(self) -> None:
        import os
        if os.getenv("TESTING") == "true":
            return

        _SECRET_KEY_PLACEHOLDER  = "your-secret-key-minimum-32-characters-here"
        _ADMIN_KEY_PLACEHOLDER   = "your-admin-api-key-minimum-32-chars-here"

        if self.secret_key == _SECRET_KEY_PLACEHOLDER:
            raise ValueError(
                "SECRET_KEY is set to the example placeholder. "
                "Generate a real secret: "
                "python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        if self.admin_api_key == _ADMIN_KEY_PLACEHOLDER:
            raise ValueError(
                "ADMIN_API_KEY is set to the example placeholder. "
                "Generate a real key: "
                "python -c \"import secrets; print('wsk_admin_' + secrets.token_hex(24))\""
            )

    def validate_cookie_security(self) -> None:
        # Fail closed in deployed environments: refusing to boot with
        # COOKIE_SECURE=false forces the operator to fix the misconfig
        # instead of silently issuing session cookies over plain HTTP.
        import os
        if os.getenv("TESTING") == "true":
            return

        env = (self.environment or "").strip().lower()
        if env in ("staging", "production") and not self.cookie_secure:
            raise ValueError(
                f"COOKIE_SECURE must be true when ENVIRONMENT={self.environment!r}. "
                "Session cookies are issued over plain HTTP otherwise. "
                "Set COOKIE_SECURE=true (default) and terminate TLS at the "
                "reverse proxy, or set ENVIRONMENT=development for local HTTP."
            )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_thresholds()
    settings.validate_secrets()
    settings.validate_cookie_security()
    return settings
