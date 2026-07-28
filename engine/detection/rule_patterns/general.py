# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
General-purpose rule patterns for threat detection.
These patterns cover broad attack categories applicable to any industry.

Industry-specific pattern sets (healthcare, finance, etc.) are added in v2
as separate modules in this package, selected via DetectorProfile.rule_patterns.
"""

import re
from domain.enums import ThreatCategory


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


# Compiled registry: (compiled_patterns, threat_category, base_score)
#
# Every pattern is compiled with re.IGNORECASE | re.DOTALL. DOTALL is applied
# uniformly across all five pattern groups to close a multi-line evasion path:
# without it, a payload like `ignore\nprevious\ninstructions` splits the `\s+`
# whitespace anchor across a line break, and `.` inside a group like
# `(all\s+)?` cannot span the newline -- letting the attacker slip past what
# looks like a straightforward `ignore previous instructions` match. DOTALL
# makes `.` match `\n` as well, so the same regex catches both the single-line
# and multi-line rendering of the same intent.
#
# Trade-off: no pattern in this file uses a greedy `.*` between anchors that
# would blow up runtime under DOTALL. If future patterns add spanning `.*`,
# re-audit for catastrophic backtracking against long multi-line inputs.
COMPILED_REGISTRY: list[tuple[list[re.Pattern], ThreatCategory, float]] = [
    (
        [re.compile(p, re.IGNORECASE | re.DOTALL) for p in PROMPT_INJECTION_PATTERNS],
        ThreatCategory.PROMPT_INJECTION,
        0.85,
    ),
    (
        [re.compile(p, re.IGNORECASE | re.DOTALL) for p in JAILBREAK_PATTERNS],
        ThreatCategory.JAILBREAK,
        0.88,
    ),
    (
        [re.compile(p, re.IGNORECASE | re.DOTALL) for p in MALICIOUS_INTENT_PATTERNS],
        ThreatCategory.MALICIOUS_INTENT,
        0.82,
    ),
    (
        [re.compile(p, re.IGNORECASE | re.DOTALL) for p in DATA_EXFILTRATION_PATTERNS],
        ThreatCategory.DATA_EXFILTRATION,
        0.80,
    ),
    (
        [re.compile(p, re.IGNORECASE | re.DOTALL) for p in TOXICITY_PATTERNS],
        ThreatCategory.TOXICITY,
        0.75,
    ),
]
