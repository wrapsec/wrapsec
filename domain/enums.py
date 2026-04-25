from enum import Enum


class DecisionType(str, Enum):
    BLOCK    = "BLOCK"
    SANITIZE = "SANITIZE"
    ALLOW    = "ALLOW"


class RiskLevel(str, Enum):
    CRITICAL = "critical"   # >= 0.9
    HIGH     = "high"       # >= 0.7
    MEDIUM   = "medium"     # >= 0.4
    LOW      = "low"        # < 0.4


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


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    OPENAI = "openai"
    GROQ   = "groq"


class PrincipalType(str, Enum):
    USER       = "user"
    API_KEY    = "api_key"
    AGENT      = "agent"       # Phase 3 stub — not implemented in v1
    MCP_CLIENT = "mcp_client"  # Phase 3 stub — not implemented in v1


class UserRole(str, Enum):
    ADMIN     = "ADMIN"
    DEVELOPER = "DEVELOPER"
    VIEWER    = "VIEWER"


class AdminEventAction(str, Enum):
    """
    Enum-controlled action values for admin_events table.
    user_updated is intentionally excluded — every update emits a specific action.
    If a single PATCH changes both role and dept_id, emit both role_changed
    and dept_changed as separate admin_event rows.
    """
    USER_CREATED     = "user_created"
    USER_DEACTIVATED = "user_deactivated"
    USER_REACTIVATED = "user_reactivated"
    PASSWORD_RESET   = "password_reset"
    ROLE_CHANGED     = "role_changed"
    DEPT_CHANGED     = "dept_changed"


class AuthEventAction(str, Enum):
    """
    Enum-controlled action values for auth_events table.
    """
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED  = "login_failed"


class AuthFailureReason(str, Enum):
    """
    Enum-controlled failure_reason values for auth_events.
    account_disabled — is_active=False set administratively
    account_inactive — user exists but is_active=False (operational state)
    """
    INVALID_PASSWORD = "invalid_password"
    USER_NOT_FOUND   = "user_not_found"
    ACCOUNT_DISABLED = "account_disabled"
    ACCOUNT_INACTIVE = "account_inactive"
    TOKEN_EXPIRED    = "token_expired"


def get_risk_level(score: float) -> RiskLevel:
    if score >= 0.9:
        return RiskLevel.CRITICAL
    elif score >= 0.7:
        return RiskLevel.HIGH
    elif score >= 0.4:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
