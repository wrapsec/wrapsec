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


def get_risk_level(score: float) -> RiskLevel:
    if score >= 0.9:
        return RiskLevel.CRITICAL
    elif score >= 0.7:
        return RiskLevel.HIGH
    elif score >= 0.4:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW