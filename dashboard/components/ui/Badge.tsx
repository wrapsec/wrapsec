// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { Decision, ThreatCategory } from "@/lib/types"
import { THREAT_LABELS } from "@/lib/constants"

// ── DecisionBadge ─────────────────────────────────────────────────────────

const DECISION_STYLES: Record<string, React.CSSProperties> = {
  BLOCK:    { background: "#fef2f2", color: "#b91c1c", border: "1px solid #fecaca" },
  SANITIZE: { background: "#fffbeb", color: "#92400e", border: "1px solid #fde68a" },
  ALLOW:    { background: "rgba(0,225,255,0.10)", color: "#0369a1", border: "1px solid rgba(0,225,255,0.35)" },
}

export function DecisionBadge({ decision, size = "md" }: { decision: Decision; size?: "sm" | "md" }) {
  const style = DECISION_STYLES[decision] ?? { background: "#f3f4f6", color: "#374151", border: "1px solid #e5e7eb" }
  return (
    <span style={{
      display:      "inline-flex",
      alignItems:   "center",
      padding:      size === "sm" ? "2px 7px" : "3px 8px",
      fontSize:     "11px",
      fontWeight:   600,
      borderRadius: "5px",
      letterSpacing:"0.02em",
      ...style,
    }}>
      {decision}
    </span>
  )
}

// ── ThreatBadge ───────────────────────────────────────────────────────────

const THREAT_STYLES: Record<string, React.CSSProperties> = {
  PROMPT_INJECTION:  { background: "#fef2f2", color: "#b91c1c", border: "1px solid #fecaca" },
  JAILBREAK:         { background: "rgba(103,15,239,0.07)", color: "#5b21b6", border: "1px solid rgba(103,15,239,0.20)" },
  MALICIOUS_INTENT:  { background: "#fff7ed", color: "#c2410c", border: "1px solid #fed7aa" },
  DATA_EXFILTRATION: { background: "rgba(0,177,255,0.08)", color: "#0369a1", border: "1px solid rgba(0,177,255,0.25)" },
  PII:               { background: "rgba(205,0,255,0.07)", color: "#86198f", border: "1px solid rgba(205,0,255,0.20)" },
  TOXICITY:          { background: "#fff1f2", color: "#be123c", border: "1px solid #fecdd3" },
}

export function ThreatBadge({ threat }: { threat: ThreatCategory }) {
  const style = THREAT_STYLES[threat] ?? { background: "#f3f4f6", color: "#374151", border: "1px solid #e5e7eb" }
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 7px", fontSize: "11px", fontWeight: 500, borderRadius: "5px",
      ...style,
    }}>
      {THREAT_LABELS[threat] || threat}
    </span>
  )
}
