# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import re
from engine.detection.base import BaseDetector, DetectionResult
from domain.enums import ThreatCategory


# ── Pattern definitions ───────────────────────────────────────

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"disregard\s+(all\s+)?previous\s+instructions?",
    r"forget\s+(all\s+)?previous\s+instructions?",
    r"override\s+(all\s+)?previous\s+instructions?",
    r"do\s+not\s+follow\s+(your\s+)?instructions?",
    r"bypass\s+(your\s+)?(instructions?|guidelines?|rules?)",
    r"ignore\s+(your\s+)?(guidelines?|rules?|constraints?)",
    r"you\s+are\s+now\s+(a\s+)?(different|new|unrestricted|evil)",
    r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(different|evil|unrestricted)",
    r"act\s+as\s+if\s+you\s+have\s+no\s+(restrictions?|guidelines?|rules?)",
    r"from\s+now\s+on\s+(you\s+are|ignore|forget)",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*(ignore|forget|override)",
]

JAILBREAK_PATTERNS = [
    r"\bdan\s+mode\b",
    r"\bdeveloper\s+mode\b",
    r"\bjailbreak\b",
    r"\bunrestricted\s+mode\b",
    r"\bgod\s+mode\b",
    r"do\s+anything\s+now",
    r"no\s+restrictions?\s+(mode|enabled)",
    r"disable\s+(your\s+)?(safety|filter|restriction|guideline)",
    r"you\s+have\s+no\s+(restrictions?|limits?|guidelines?)",
    r"without\s+(any\s+)?(restriction|filter|limitation|safety)",
    r"simulate\s+(a\s+)?(unrestricted|evil|unfiltered)",
    r"hypothetically\s+(speaking\s+)?if\s+you\s+(had\s+no|were\s+unrestricted)",
]

MALICIOUS_INTENT_PATTERNS = [
    r"how\s+to\s+(make|build|create|synthesize)\s+(a\s+)?(bomb|weapon|explosive|virus|malware)",
    r"how\s+to\s+(hack|attack|exploit|compromise)\s+",
    r"how\s+to\s+(steal|phish|scam|defraud)\s+",
    r"how\s+to\s+kill\s+",
    r"how\s+to\s+(bypass|defeat|disable)\s+(security|firewall|authentication|2fa)",
    r"(create|write|generate)\s+(a\s+)?(malware|ransomware|virus|trojan|keylogger)",
    r"(create|write|generate)\s+(a\s+)?phishing\s+(email|page|site)",
    r"(sql|command|code)\s+injection\s+(attack|exploit|payload)",
    r"(ddos|dos)\s+attack",
    r"brute\s+force\s+(attack|password|login)",
    r"zero.?day\s+(exploit|vulnerability|attack)",
    r"(steal|exfiltrate|leak)\s+(user\s+)?(data|credentials|passwords?|tokens?)",
]

DATA_EXFILTRATION_PATTERNS = [
    r"send\s+(all\s+)?(user\s+)?(data|information|records?)\s+to\s+",
    r"(upload|export|transmit)\s+(all\s+)?(data|records?|files?)\s+to\s+",
    r"(reveal|expose|leak|share)\s+(all\s+)?(user\s+)?(data|information|credentials?)",
    r"(dump|extract)\s+(all\s+)?(database|db|table|records?)",
    r"(show|list|print)\s+(all\s+)?(users?|passwords?|credentials?|api.?keys?)",
    r"(access|read|get)\s+(all\s+)?(private|secret|confidential)\s+(data|files?|keys?)",
]

TOXICITY_PATTERNS = [
    r"\b(kill|murder|rape|torture)\s+(yourself|himself|herself|themselves)\b",
    r"\b(you\s+should|go\s+and)\s+(die|kill\s+yourself)\b",
    r"\bfuck\s+(you|off|this)\b",
    r"\b(hate|despise)\s+(all\s+)?(jews?|muslims?|christians?|blacks?|whites?|asians?)\b",
]

# Compiled pattern registry
_REGISTRY: list[tuple[list, ThreatCategory, float]] = [
    (PROMPT_INJECTION_PATTERNS, ThreatCategory.PROMPT_INJECTION, 0.85),
    (JAILBREAK_PATTERNS,        ThreatCategory.JAILBREAK,        0.88),
    (MALICIOUS_INTENT_PATTERNS, ThreatCategory.MALICIOUS_INTENT, 0.82),
    (DATA_EXFILTRATION_PATTERNS,ThreatCategory.DATA_EXFILTRATION,0.80),
    (TOXICITY_PATTERNS,         ThreatCategory.TOXICITY,         0.75),
]

_COMPILED: list[tuple[list[re.Pattern], ThreatCategory, float]] = [
    (
        # re.DOTALL allows multi-line injection payloads (e.g. "ignore\nprevious")
        # to be matched by single-line patterns. Most patterns use \s not .,
        # but DOTALL is kept so patterns added in future need not opt in explicitly.
        [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns],
        category,
        base_score,
    )
    for patterns, category, base_score in _REGISTRY
]


class RuleDetector(BaseDetector):

    @property
    def name(self) -> str:
        return "rule_detector"

    def detect(self, text: str) -> DetectionResult:
        try:
            threats    = []
            max_score  = 0.0
            details    = {}

            for compiled_patterns, category, base_score in _COMPILED:
                matched = [
                    p.pattern for p in compiled_patterns
                    if p.search(text)
                ]
                if matched:
                    threats.append(category)
                    # Score is the max across all matching categories, not a sum.
                    # Multi-category hits do not boost the score - each category
                    # has a calibrated base_score that already reflects severity.
                    # The list of threat categories in `threats` carries the
                    # multi-category signal for policy and audit purposes.
                    max_score = max(max_score, base_score)
                    details[category.value] = matched

            return DetectionResult(
                score     = max_score,
                threats   = threats,
                triggered = max_score > 0.0,
                detector  = self.name,
                details   = details if details else None,
            )

        except Exception:
            return DetectionResult.clean(self.name)