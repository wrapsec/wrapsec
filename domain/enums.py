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
    off by default).

    agent_tool_call is arguments a model composed for a tool invocation. It is
    untrusted by default and deliberately NOT user_prompt: a human typed the
    latter, whereas the former is text a model produced, and an injected
    instruction becomes an ACTION at exactly this boundary -- the last gate
    before a side effect that may not be reversible."""
    USER_PROMPT        = "user_prompt"
    TOOL_OUTPUT        = "tool_output"
    RETRIEVED_DOCUMENT = "retrieved_document"
    EXTERNAL_CONTENT   = "external_content"
    AGENT_TOOL_CALL    = "agent_tool_call"


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
    # Clearing a lockout restores the ability to authenticate, so it is
    # recorded like any other change to who can get in.
    ACCOUNT_UNLOCKED = "account_unlocked"
    # A create refused because the address is already registered -- possibly in
    # a tenant this administrator cannot see. The refusal is unavoidable while
    # identity is global, so the probe is recorded rather than concealed.
    USER_CREATE_REJECTED_EXISTING_EMAIL = "user_create_rejected_existing_email"
    ROLE_CHANGED     = "role_changed"
    DEPT_CHANGED     = "dept_changed"
    # Changing where a credential may be used is a change to a security
    # boundary, so it is recorded separately from other key edits: a
    # restriction an administrator can quietly remove is a weak control.
    KEY_ALLOWLIST_CHANGED   = "key_allowlist_changed"
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
    # A machine credential refused because it was presented from an address
    # its owner did not permit. Not a sign-in: there is no user and no
    # password, which is why the row carries a credential rather than a user.
    API_KEY_IP_DENIED     = "api_key_ip_denied"


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
    # The presented address is outside the networks configured on the credential.
    IP_NOT_ALLOWED      = "ip_not_allowed"
    EXPIRED             = "expired"
    REFRESH_FAILED      = "refresh_failed"
    # A refresh token that was issued, rotated away, and then presented again.
    # Distinct from REFRESH_FAILED on purpose: an ordinary bad token says
    # nothing, while a replay means a token escaped its owner and every session
    # for that user was revoked in response. An operator reading the event
    # stream needs to tell those apart.
    #
    # Must exist here or the event is silently dropped: the writer coerces the
    # reason through this enum and the failure is swallowed by its handler, so
    # an unlisted reason produces a log line and no audit row.
    TOKEN_REUSE_DETECTED = "token_reuse_detected"
    SESSION_INVALIDATED = "session_invalidated"
    NO_MEMBERSHIP       = "no_membership"


class LogoutReason(str, Enum):
    """
    Valid reason values accepted by POST /v1/auth/logout.
    Frontend input is validated against this enum - invalid values
    are normalized to MANUAL silently (never raise 400).
    """
    MANUAL     = "manual"
    INACTIVITY = "inactivity"
    EXPIRED    = "expired"


class NotificationCategory(str, Enum):
    """Grouping for notification event identifiers."""
    ACCOUNT      = "account"
    API_SECURITY = "api_security"
    SECURITY     = "security"   # reserved for V2 (critical.security_event)


class NotificationType(str, Enum):
    """
    Canonical `<namespace>.<event>` transactional notification identifiers
    (v1.8.3), grouped by category. Three distinct states -- do NOT conflate them
    (see IMPLEMENTED_NOTIFICATIONS and services.email):

        Registered  -- a known event: any member of this enum.
        Implemented -- registered AND has a subject, per-locale templates, and a
                       context contract, so it can be rendered
                       (IMPLEMENTED_NOTIFICATIONS). A registered-but-not-
                       implemented member is *reserved*.
        Sendable    -- implemented AND runtime-enabled (the notifications master
                       switch is on); decided at enqueue time in EmailService.

    Reserved members exist so the event contract is stable and future events
    slot in without renaming. To promote a reserved event: add it to
    IMPLEMENTED_NOTIFICATIONS, give it a subject (notifications catalog), HTML +
    text templates per locale, a REQUIRED_CONTEXT entry, and a trigger.
    """
    # ACCOUNT
    USER_INVITED            = "user.invited"             # reserved
    PASSWORD_CHANGED        = "password.changed"         # implemented
    PASSWORD_RESET_BY_ADMIN = "password.reset_by_admin"  # implemented
    ACCOUNT_LOCKED          = "account.locked"           # implemented
    ACCOUNT_DEACTIVATED     = "account.deactivated"      # implemented
    ACCOUNT_REACTIVATED     = "account.reactivated"      # implemented
    ROLE_CHANGED            = "role.changed"             # implemented
    # API SECURITY
    API_KEY_CREATED         = "api_key.created"          # reserved
    API_KEY_REVOKED         = "api_key.revoked"          # reserved
    # SECURITY
    #   critical.security_event -- reserved for V2, intentionally NOT defined
    #   until it ships.


# Every registered notification type maps to exactly one category (guarded).
NOTIFICATION_CATEGORY: dict[NotificationType, NotificationCategory] = {
    NotificationType.USER_INVITED:            NotificationCategory.ACCOUNT,
    NotificationType.PASSWORD_CHANGED:        NotificationCategory.ACCOUNT,
    NotificationType.PASSWORD_RESET_BY_ADMIN: NotificationCategory.ACCOUNT,
    NotificationType.ACCOUNT_LOCKED:          NotificationCategory.ACCOUNT,
    NotificationType.ACCOUNT_DEACTIVATED:     NotificationCategory.ACCOUNT,
    NotificationType.ACCOUNT_REACTIVATED:     NotificationCategory.ACCOUNT,
    NotificationType.ROLE_CHANGED:            NotificationCategory.ACCOUNT,
    NotificationType.API_KEY_CREATED:         NotificationCategory.API_SECURITY,
    NotificationType.API_KEY_REVOKED:         NotificationCategory.API_SECURITY,
}

# The subset that actually sends email today. Everything else is *reserved*:
# registered (a stable identifier) but not implemented, so EmailService skips it.
IMPLEMENTED_NOTIFICATIONS: frozenset[NotificationType] = frozenset({
    NotificationType.PASSWORD_CHANGED,
    NotificationType.PASSWORD_RESET_BY_ADMIN,
    NotificationType.ACCOUNT_LOCKED,
    NotificationType.ACCOUNT_DEACTIVATED,
    NotificationType.ACCOUNT_REACTIVATED,
    NotificationType.ROLE_CHANGED,
})


def is_implemented(notification_type: NotificationType) -> bool:
    """True if the type has full rendering support and may be enqueued. A
    registered-but-not-implemented type is reserved (EmailService skips it)."""
    return notification_type in IMPLEMENTED_NOTIFICATIONS


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
