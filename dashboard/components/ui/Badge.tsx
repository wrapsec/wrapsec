// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useTranslations } from "next-intl"
import { Decision, ThreatCategory } from "@/lib/types"
import { THREAT_LABELS, contentSourceLabel, isUntrustedSource } from "@/lib/constants"

// One badge geometry for the whole dashboard: identical padding, font size,
// weight, radius, and border width across Decision / Threat / Severity / Mode /
// Source so a row of mixed badges lines up. Only the colors vary per badge.
const BADGE_BASE: React.CSSProperties = {
  display:       "inline-flex",
  alignItems:    "center",
  padding:       "2px 8px",
  fontSize:      "11px",
  fontWeight:    600,
  lineHeight:    1.45,
  borderRadius:  "6px",
  whiteSpace:    "nowrap",
}

const NEUTRAL = { background: "#f3f4f6", color: "#374151", border: "1px solid #e5e7eb" }

// --- DecisionBadge ---

const DECISION_STYLES: Record<string, React.CSSProperties> = {
  BLOCK:    { background: "#fef2f2", color: "#b91c1c", border: "1px solid #fecaca" },
  SANITIZE: { background: "#fffbeb", color: "#92400e", border: "1px solid #fde68a" },
  ALLOW:    { background: "rgba(0,225,255,0.10)", color: "#0369a1", border: "1px solid rgba(0,225,255,0.35)" },
}

export function DecisionBadge({ decision }: { decision: Decision; size?: "sm" | "md" }) {
  return (
    <span style={{ ...BADGE_BASE, letterSpacing: "0.02em", ...(DECISION_STYLES[decision] ?? NEUTRAL) }}>
      {decision}
    </span>
  )
}

// --- ThreatBadge ---

const THREAT_STYLES: Record<string, React.CSSProperties> = {
  PROMPT_INJECTION:  { background: "#fef2f2", color: "#b91c1c", border: "1px solid #fecaca" },
  JAILBREAK:         { background: "rgba(103,15,239,0.07)", color: "#5b21b6", border: "1px solid rgba(103,15,239,0.20)" },
  MALICIOUS_INTENT:  { background: "#fff7ed", color: "#c2410c", border: "1px solid #fed7aa" },
  DATA_EXFILTRATION: { background: "rgba(0,177,255,0.08)", color: "#0369a1", border: "1px solid rgba(0,177,255,0.25)" },
  PII:               { background: "rgba(205,0,255,0.07)", color: "#86198f", border: "1px solid rgba(205,0,255,0.20)" },
  TOXICITY:          { background: "#fff1f2", color: "#be123c", border: "1px solid #fecdd3" },
}

export function ThreatBadge({ threat }: { threat: ThreatCategory }) {
  return (
    <span style={{ ...BADGE_BASE, ...(THREAT_STYLES[threat] ?? NEUTRAL) }}>
      {THREAT_LABELS[threat] || threat}
    </span>
  )
}

// --- SeverityBadge ---

// Text colors darkened to clear WCAG AA (>=4.5:1) against each badge's own tinted
// background; the backgrounds/borders are unchanged so the palette still reads the same.
const SEVERITY_STYLES: Record<string, React.CSSProperties> = {
  CRITICAL: { color: "#b91c1c", background: "rgba(220,38,38,0.08)",   border: "1px solid rgba(220,38,38,0.20)"   },
  HIGH:     { color: "#b45309", background: "rgba(217,119,6,0.08)",   border: "1px solid rgba(217,119,6,0.20)"   },
  MEDIUM:   { color: "#1d4ed8", background: "rgba(37,99,235,0.08)",   border: "1px solid rgba(37,99,235,0.20)"   },
  LOW:      { color: "#4b5563", background: "rgba(107,114,128,0.08)", border: "1px solid rgba(107,114,128,0.20)" },
}

export function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span style={{ fontSize: "12px", color: "#6b7280" }}>-</span>
  return (
    <span style={{ ...BADGE_BASE, ...(SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.LOW) }}>
      {severity}
    </span>
  )
}

// --- ModeBadge (detection / execution mode) ---

export function ModeBadge({ label, active }: { label: string; active: boolean }) {
  return (
    <span style={{
      ...BADGE_BASE,
      fontWeight: 500,
      border:     active ? "1px solid rgba(103,15,239,0.20)" : "1px solid #e5e7eb",
      background: active ? "rgba(103,15,239,0.06)" : "#f9fafb",
      color:      active ? "#670FEF" : "#6b7280",
    }}>
      {label}
    </span>
  )
}

// --- SourceBadge (trust-boundary provenance) ---

const SOURCE_STYLES = {
  untrusted: { background: "#fffbeb", color: "#b45309", border: "1px solid #fde68a" },
  trusted:   { background: "#f8fafc", color: "#475569", border: "1px solid #e2e8f0" },
}

export function SourceBadge({ source }: { source: string | null }) {
  const t = useTranslations("common")
  const untrusted = isUntrustedSource(source)
  return (
    <span
      style={{ ...BADGE_BASE, ...(untrusted ? SOURCE_STYLES.untrusted : SOURCE_STYLES.trusted) }}
      title={untrusted ? t("source_tooltip.untrusted") : t("source_tooltip.user")}
    >
      {contentSourceLabel(source)}
    </span>
  )
}
