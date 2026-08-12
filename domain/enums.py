# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

from enum import Enum


class DecisionType(str, Enum):
    BLOCK    = "BLOCK"
    SANITIZE = "SANITIZE"
    ALLOW    = "ALLOW"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"   # >= 0.9
    HIGH     = "HIGH"       # >= 0.7
    MEDIUM   = "MEDIUM"     # >= 0.4
    LOW      = "LOW"        # < 0.4


class ThreatCategory(str, Enum):
    PROMPT_INJECTION  = "PROMPT_INJECTION"
    JAILBREAK         = "JAILBREAK"
    MALICIOUS_INTENT  = "MALICIOUS_INTENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PII               = "PII"
    TOXICITY          = "TOXICITY"
    BENIGN            = "BENIGN"


class DetectionMode(str, Enum):
    FAST = "fast"
    FULL = "full"


class ExecutionMode(str, Enum):
    SCAN_ONLY = "scan_only"
    PROXY     = "proxy"


class InputSource(str, Enum):
    """Trust-boundary provenance of the scanned input: where the text came from.
    user_prompt is trusted-origin; the rest mark content an agent pulled in
    (tool results, retrieved documents, other external text) -- the primary
    indirect prompt-injection surface. Source never relaxes detection: identical
    content scores identically whatever origin it claims. It can, opt-in, tighten
    the policy thresholds applied to untrusted origins (source-aware posture,
    off by default)."""
    USER_PROMPT        = "user_prompt"
    TOOL_OUTPUT        = "tool_output"
    RETRIEVED_DOCUMENT = "retrieved_document"
    EXTERNAL_CONTENT   = "external_content"


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    OPENAI = "openai"
    GROQ   = "groq"


class PrincipalType(str, Enum):
    USER       = "user"
    API_KEY    = "api_key"
    AGENT      = "agent"       # Phase 3 stub - not implemented in v1
    MCP_CLIENT = "mcp_client"  # Phase 3 stub - not implemented in v1


class UserRole(str, Enum):
    ADMIN     = "ADMIN"
    DEVELOPER = "DEVELOPER"
    VIEWER    = "VIEWER"
    # Read-only role scoped for audit and compliance work. Distinct from
    # VIEWER: also carries settings:read and keys:read so a SOC2/ISO auditor
    # can inspect policy configuration and API key inventory without any
    # write path.
    AUDITOR   = "AUDITOR"


class AdminEventAction(str, Enum):
    """
    Enum-controlled action values for admin_events table.
    user_updated is intentionally excluded - every update emits a specific action.
    If a single PATCH changes both role and dept_id, emit both role_changed
    and dept_changed as separate admin_event rows.
    """
    USER_CREATED     = "user_created"
    USER_DEACTIVATED = "user_deactivated"
    USER_REACTIVATED = "user_reactivated"
    PASSWORD_RESET   = "password_reset"
    ROLE_CHANGED     = "role_changed"
    DEPT_CHANGED     = "dept_changed"
    SETTINGS_CHANGED        = "settings_changed"
    POLICY_OVERRIDE_CHANGED = "policy_override_changed"
    # Webhook endpoint lifecycle (v1.3.0). Every mutation to a
    # webhook_endpoints row emits one of these so a tenant admin can
    # reconstruct who added/changed/removed a destination and when a
    # signing secret was last rotated. WEBHOOK_SECRET_ROTATED is the
    # single trigger for "plaintext secret was returned in an HTTP
    # response" -- that side-effect must always be audit-visible.
    WEBHOOK_ENDPOINT_CREATED     = "webhook_endpoint_created"
    WEBHOOK_ENDPOINT_UPDATED     = "webhook_endpoint_updated"
    WEBHOOK_ENDPOINT_DELETED     = "webhook_endpoint_deleted"
    WEBHOOK_ENDPOINT_PAUSED      = "webhook_endpoint_paused"
    WEBHOOK_ENDPOINT_REACTIVATED = "webhook_endpoint_reactivated"
    WEBHOOK_SECRET_ROTATED       = "webhook_secret_rotated"
    # Admin-triggered synthetic test delivery. Audited because it makes the
    # server issue an outbound request to the configured destination.
    WEBHOOK_ENDPOINT_TESTED      = "webhook_endpoint_tested"


class AuthEventAction(str, Enum):
    """
    Enum-controlled action values for auth_events table.
    Each value is owned by exactly one logging location - never duplicated.
    See session_management.md §Logging Ownership for the full ownership map.
    """
    LOGIN_SUCCESS         = "login_success"
    LOGIN_FAILED          = "login_failed"
    LOGOUT                = "logout"
    TOKEN_REFRESH_SUCCESS = "token_refresh_success"
    TOKEN_REFRESH_FAILED  = "token_refresh_failed"
    SESSION_EXPIRED       = "session_expired"


class AuthFailureReason(str, Enum):
    """
    Enum-controlled failure_reason values for auth_events.
    account_disabled - is_active=False set administratively
    account_inactive - user exists but is_active=False (operational state)
    token_invalid    - malformed or tampered JWT (distinct from token_expired)
    """
    INVALID_PASSWORD    = "invalid_password"
    USER_NOT_FOUND      = "user_not_found"
    ACCOUNT_DISABLED    = "account_disabled"
    ACCOUNT_INACTIVE    = "account_inactive"
    TOKEN_EXPIRED       = "token_expired"
    TOKEN_INVALID       = "token_invalid"
    INACTIVITY          = "inactivity"
    MANUAL              = "manual"
    EXPIRED             = "expired"
    REFRESH_FAILED      = "refresh_failed"
    SESSION_INVALIDATED = "session_invalidated"


class LogoutReason(str, Enum):
    """
    Valid reason values accepted by POST /v1/auth/logout.
    Frontend input is validated against this enum - invalid values
    are normalized to MANUAL silently (never raise 400).
    """
    MANUAL     = "manual"
    INACTIVITY = "inactivity"
    EXPIRED    = "expired"


class NotificationType(str, Enum):
    """
    Transactional email notification types (v1.8.3).

    V1 ships only minimal, informational security notifications, all triggered
    by an authenticated or internal action. Each value maps 1:1 to a subject
    key under the `notifications` locale namespace and a pair of per-locale
    body templates (HTML + text). Self-service password reset is intentionally
    absent: it is deferred to a later release as its own security mini-project.
    """
    PASSWORD_CHANGED     = "password_changed"       # user changed their own password
    ADMIN_PASSWORD_RESET = "admin_password_reset"   # an admin reset the user's password
    ACCOUNT_LOCKED       = "account_locked"         # lockout after repeated failed logins


class EmailStatus(str, Enum):
    """
    Lifecycle of an email_outbox row (v1.8.3).

    Names are deliberately honest about what WrapSec actually knows over plain
    SMTP: PROVIDER_ACCEPTED means the configured SMTP server accepted the
    message for relay -- it is NOT proof of recipient delivery. DELIVERED and
    BOUNCED are reserved for a future transactional-provider capability that
    reports real delivery events; the SMTP-only V1 never sets them.
    """
    QUEUED            = "queued"             # committed to the outbox, awaiting a worker
    SENDING           = "sending"            # a worker has claimed the row
    PROVIDER_ACCEPTED = "provider_accepted"  # SMTP server accepted the message for relay
    FAILED            = "failed"             # non-retryable, or retries exhausted


def get_risk_level(score: float) -> RiskLevel:
    if score >= 0.9:
        return RiskLevel.CRITICAL
    elif score >= 0.7:
        return RiskLevel.HIGH
    elif score >= 0.4:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
