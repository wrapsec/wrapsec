export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

export const DECISION_COLORS = {
  BLOCK:    { text: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  SANITIZE: { text: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  ALLOW:    { text: "#16a34a", bg: "#f0fdf4", border: "#bbf7d0" },
} as const

export const THREAT_LABELS: Record<string, string> = {
  PROMPT_INJECTION:  "Prompt Injection",
  JAILBREAK:         "Jailbreak",
  MALICIOUS_INTENT:  "Malicious Intent",
  DATA_EXFILTRATION: "Data Exfiltration",
  PII:               "PII",
  TOXICITY:          "Toxicity",
}

export const CHART_COLORS = {
  BLOCK:    "#dc2626",
  SANITIZE: "#f97316",
  ALLOW:    "#22c55e",
  rule:     "#3b82f6",
  ml:       "#8b5cf6",
  llm:      "#f59e0b",
} as const

export const POLL_INTERVAL = 10000 // 10 seconds

export const PAGE_SIZE = 20
// ── Valid URL param values — derived from existing constants ─────────────────
// Single source of truth: if DECISION_COLORS or THREAT_LABELS change,
// these update automatically. No separate maintenance needed.
export const VALID_DECISIONS  = Object.keys(DECISION_COLORS)  // ["BLOCK", "SANITIZE", "ALLOW"]
export const VALID_THREATS    = Object.keys(THREAT_LABELS)     // ["PROMPT_INJECTION", ...]
export const VALID_EXEC_MODES = ["scan_only", "proxy"] as const // ExecutionMode from types.ts
