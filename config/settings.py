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

    # ── Security ──────────────────────────────────────────────
    secret_key:      str = Field(..., min_length=32)
    jwt_algorithm:   str = "HS256"
    jwt_expiry_mins: int = 60
    admin_api_key:   str = Field(...)

    # ── Database ──────────────────────────────────────────────
    database_url:    str = Field(...)
    db_pool_size:    int = 10
    db_max_overflow: int = 20

    # ── Redis ─────────────────────────────────────────────────
    redis_url:       str = Field(default="redis://localhost:6379/0")
    redis_ttl:       int = 3600

    # ── Rate Limiting ─────────────────────────────────────────
    rate_limit_enabled:      bool = True
    rate_limit_per_minute:   int  = 60
    rate_limit_burst:        int  = 10

    # ── Audit log retention ────────────────────────────────────
    audit_retention_days:    int  = 30  # days to keep audit logs in DB

    # ── Detection Engine ──────────────────────────────────────
    default_detection_mode:  str   = "fast"
    default_execution_mode:  str   = "scan_only"
    block_threshold:         float = 0.7
    sanitize_threshold:      float = 0.4
    llm_trigger_threshold:   float = 0.2

    # ── LLM Provider ──────────────────────────────────────────
    llm_provider:    str = Field(default="ollama")  # ollama | openai | groq
    llm_model:       str = Field(default="llama3.2")
    llm_base_url:    str = Field(default="http://localhost:11434")
    openai_api_key:  str = Field(default="")
    groq_api_key:    str = Field(default="")
    llm_timeout:     int = 30

    # ── Idempotency ───────────────────────────────────────────
    idempotency_window_secs: int = 60

    # ── Observability ─────────────────────────────────────────
    log_level:               str  = "INFO"
    log_format:              str  = "json"
    prometheus_enabled:      bool = True
    prometheus_port:         int  = 9090

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

    def validate_thresholds(self) -> None:
        if self.block_threshold <= self.sanitize_threshold:
            raise ValueError(
                f"block_threshold ({self.block_threshold}) must be greater "
                f"than sanitize_threshold ({self.sanitize_threshold})"
            )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_thresholds()
    return settings