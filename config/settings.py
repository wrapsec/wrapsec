# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

# Static catalog of configurable PLUGIN-capability names -- the single source of
# truth for valid WRAPSEC_FEATURES entries. It contains ONLY capabilities
# governed by the plugin registry + ceiling. It deliberately excludes:
#   - always-on core (api/sdk/dashboard/rules/ml)
#   - per-principal capabilities (proxy -- governed by API-key authorization)
#   - per-build capabilities (transformer -- governed by BUILD_ENV/dependency)
# WRAPSEC_FEATURES is validated against this at startup (an ordering constraint:
# config is parsed before plugins register, so we cannot validate against the
# live registry). Add names here only as real plugin capabilities land.
CONFIGURABLE_CAPABILITIES: frozenset[str] = frozenset({"mcp"})


class Settings(BaseSettings):

    # ── Application ───────────────────────────────────────────
    app_name:        str = "WrapSec"
    app_version:     str = "1.0.0"
    debug:           bool = False
    # Runtime posture. Production is the SAFE DEFAULT: an unset/empty ENVIRONMENT
    # resolves to "production", so a fresh install gets production security
    # behavior (e.g. the COOKIE_SECURE fail-closed guard) rather than silently
    # running as development. An explicit invalid value fails startup. Dev and
    # test set ENVIRONMENT=development explicitly.
    environment:     Literal["development", "staging", "production"] = "production"

    @field_validator("environment", mode="before")
    @classmethod
    def _normalize_environment(cls, v: object) -> str:
        val = (str(v) if v is not None else "").strip().lower()
        if not val:
            return "production"   # missing/empty -> production-safe default
        if val not in ("development", "staging", "production"):
            raise ValueError(
                f"ENVIRONMENT must be development|staging|production (got {v!r}); "
                "unset defaults to production"
            )
        return val

    # Localization config (supported_locales / default_locale / catalog_version)
    # is NOT here: locales/_meta.json is the single source of truth, read via
    # services.localization. Keeping it out of settings prevents a second,
    # drift-prone copy (see the error-handling/localization rules doc).

    # ── Capabilities ──────────────────────────────────────────
    # Optional ceiling over the PLUGIN capability layer only. Comma-separated
    # capability names (e.g. "mcp"). UNSET/empty means NO restriction (all
    # registered plugin capabilities are available) -- required so existing
    # private plugins keep working without a new env var. Names are validated
    # against CONFIGURABLE_CAPABILITIES at startup; an unknown name (e.g. a typo
    # "proxi") fails startup rather than being silently accepted. This ceiling
    # NEVER touches core, per-principal (proxy), or per-build (transformer)
    # gating, and can only restrict availability -- never grant it.
    wrapsec_features: str | None = Field(default=None)

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

    # -- Source-aware policy posture (opt-in) ------------------
    # Trust-boundary provenance drives policy strictness, never detection.
    # Each scan carries an input_source (domain.enums.InputSource); the Source
    # Registry classifies it into a trust tier and the Policy Adapter tightens
    # the block/sanitize thresholds for untrusted origins. Fully opt-in:
    # untrusted_threshold_delta defaults to 0.0, so behavior is unchanged until
    # an operator sets it. Detection output is identical regardless of source --
    # a caller cannot weaken detection by misdeclaring provenance.
    trusted_input_sources:      list[str] = Field(
        default_factory=lambda: ["user_prompt"]
    )
    untrusted_input_sources:    list[str] = Field(
        default_factory=lambda: ["tool_output", "retrieved_document", "external_content"]
    )
    # A source in neither list resolves to the "unknown" tier. By default
    # unknown gets BASE posture (no tightening) so a newly introduced source
    # never surprise-blocks on upgrade; set true for a full Zero-Trust stance
    # where anything unclassified is treated as untrusted.
    treat_unknown_as_untrusted: bool  = False
    # Amount to LOWER the block AND sanitize thresholds for untrusted sources
    # (both shifted by the same delta, so block > sanitize is preserved). 0.0
    # disables the feature; a calibrated recommendation ships in the docs.
    untrusted_threshold_delta:  float = 0.0

    # -- Batch scanning ----------------------------------------
    # POST /v1/ai/scan-batch scans many items in one call. max_batch_items
    # bounds the fan-out (and the rate-limit amplification, since a batch is
    # charged as N units); batch_concurrency bounds how many items run the
    # detection pipeline in parallel per request.
    max_batch_items:   int = 50
    batch_concurrency: int = 8

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
    # The delivery worker loop is started in the API lifespan. Set _ENABLED=
    # false to run the API without draining the queue (e.g. a dedicated worker
    # process, or tests). Concurrency caps in-flight receiver requests.
    webhook_delivery_worker_enabled:     bool = True
    webhook_delivery_concurrency:        int  = 8

    # -- Webhook egress SSRF guard --
    # Webhook destinations are external SIEMs, so egress is locked down
    # secure-by-default. This is DISTINCT from the LLM proxy target (LLM_
    # PROVIDER url), which is often an internal service and stays permissive --
    # a self-hosted gateway in front of an in-cluster LLM keeps working.
    # The destination host is resolved at connect time and blocked if any
    # resolved IP is private/loopback/link-local/metadata. To send to an
    # on-prem SIEM on a private address, list its host or CIDR in the
    # allowlist (GitLab/GitHub "allow local network" model); or set
    # _BLOCK_PRIVATE_EGRESS=false on a fully trusted network.
    webhook_block_private_egress:        bool = True
    webhook_egress_allowlist:            str  = ""   # comma-separated hosts or CIDRs
    webhook_require_https:               bool = True

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

    # ── Email (transactional notifications, v1.8.3) ───────────────────────────
    # Email is OPTIONAL infrastructure. When smtp_host is unset the application
    # boots normally, the outbox delivery worker does not start, and business
    # actions that would send a notification still complete (the notification is
    # simply not delivered). Never make these mandatory at boot.
    #
    # smtp_use_tls   -- implicit TLS on connect (SMTPS, typically port 465).
    # smtp_start_tls -- opportunistic STARTTLS upgrade (typically port 587).
    # Set exactly one to True for a TLS connection; both False is plaintext and
    # is only appropriate for a local/test relay.
    smtp_host:                 str | None = Field(default=None)
    smtp_port:                 int  = 587
    smtp_username:             str | None = Field(default=None)
    smtp_password:             str | None = Field(default=None)
    smtp_use_tls:              bool = False
    smtp_start_tls:            bool = True
    smtp_from:                 str | None = Field(default=None)   # From: header address
    smtp_from_name:            str  = "WrapSec"                    # From: display name
    smtp_timeout_seconds:      int  = 15

    # Outbox delivery worker. Long-running poll loop started in the API lifespan
    # (like the webhook worker). Disabled automatically when smtp_host is unset;
    # _ENABLED=false also keeps it off (dedicated worker process, or tests).
    email_worker_enabled:      bool = True
    email_worker_poll_seconds: int  = 10     # idle poll interval between batches
    email_worker_batch:        int  = 20     # rows claimed per poll
    email_worker_concurrency:  int  = 5      # concurrent provider sends per batch
    # Retention for the email_outbox audit table (days). Reuses the existing
    # APScheduler retention job. Email rows carry no secrets, but they hold
    # recipient addresses (personal data), so they are not retained forever.
    email_retention_days:      int  = 30

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

    def validate_source_posture(self) -> None:
        # A negative delta would LOOSEN thresholds for untrusted sources -- the
        # opposite of the feature's intent. Reject it so a sign typo cannot
        # weaken policy for the exact origins that warrant more scrutiny.
        if self.untrusted_threshold_delta < 0:
            raise ValueError(
                f"untrusted_threshold_delta ({self.untrusted_threshold_delta}) "
                f"must be >= 0; it lowers thresholds for untrusted sources."
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

    def validate_email_config(self) -> None:
        # Email is optional: with no smtp_host there is nothing to validate and
        # the app must still boot (email disabled). Only when a host IS provided
        # do we enforce a coherent, sendable configuration so a half-configured
        # relay fails loudly at boot instead of silently dropping every message.
        import os
        if os.getenv("TESTING") == "true":
            return
        if not self.smtp_host:
            return
        if self.smtp_use_tls and self.smtp_start_tls:
            raise ValueError(
                "SMTP_USE_TLS and SMTP_START_TLS are mutually exclusive. "
                "Use SMTP_USE_TLS=true for implicit TLS (port 465) OR "
                "SMTP_START_TLS=true for STARTTLS (port 587), not both."
            )
        if not self.smtp_from:
            raise ValueError(
                "SMTP_FROM must be set when SMTP_HOST is configured "
                "(the From: address for outgoing notifications)."
            )

    def configured_features(self) -> frozenset[str] | None:
        """The WRAPSEC_FEATURES ceiling as a normalized set, or None when unset.

        None (unset/empty) means NO restriction over the plugin layer. A returned
        set is the exact ceiling: only registered plugin capabilities whose name
        is in this set are available. Whitespace and duplicates are normalized;
        an empty/whitespace value is treated as unset (no ceiling), so an empty
        ceiling can never be created accidentally.
        """
        raw = self.wrapsec_features
        if raw is None:
            return None
        names = {n.strip().lower() for n in raw.split(",") if n.strip()}
        return frozenset(names) if names else None

    def validate_capability_config(self) -> None:
        # Validate WRAPSEC_FEATURES against the static catalog (config is parsed
        # before plugins register, so the live registry cannot be used here). An
        # unknown name fails startup rather than being silently accepted.
        features = self.configured_features()
        if features is None:
            return
        unknown = sorted(features - CONFIGURABLE_CAPABILITIES)
        if unknown:
            raise ValueError(
                f"WRAPSEC_FEATURES contains unknown capability name(s): {unknown}. "
                f"Valid configurable capabilities: {sorted(CONFIGURABLE_CAPABILITIES)}. "
                "This ceiling governs plugin capabilities only -- not proxy, "
                "transformer, or core."
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
    settings.validate_source_posture()
    settings.validate_secrets()
    settings.validate_cookie_security()
    settings.validate_email_config()
    settings.validate_capability_config()
    return settings
