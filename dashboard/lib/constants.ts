// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
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
// ── Valid URL param values - derived from existing constants ─────────────────
// Single source of truth: if DECISION_COLORS or THREAT_LABELS change,
// these update automatically. No separate maintenance needed.
export const VALID_DECISIONS  = Object.keys(DECISION_COLORS)  // ["BLOCK", "SANITIZE", "ALLOW"]
export const VALID_THREATS    = Object.keys(THREAT_LABELS)     // ["PROMPT_INJECTION", ...]
export const VALID_EXEC_MODES = ["scan_only", "proxy"] as const // ExecutionMode from types.ts

// --- Content source (input_source / trust-boundary provenance) ---------------
// One home for the human labels + trust classification so the requests table,
// the detail drawer, the Sources page, and future RAG / MCP / Agent pages render
// the same wording. Trust tiers mirror the shipped backend defaults
// (config/settings.py).
export const CONTENT_SOURCE_LABELS: Record<string, string> = {
  user_prompt:        "User Prompt",
  retrieved_document: "Retrieved Document",
  tool_output:        "Tool Output",
  external_content:   "External Content",
}

const TRUSTED_CONTENT_SOURCES   = new Set(["user_prompt"])
const UNTRUSTED_CONTENT_SOURCES = new Set([
  "tool_output", "retrieved_document", "external_content",
])

/** Human label for an input_source; title-cases unknown values as a fallback. */
export function contentSourceLabel(source: string | null | undefined): string {
  const s = source ?? "user_prompt"
  return CONTENT_SOURCE_LABELS[s] ?? s.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())
}

/** Trust classification of a content source (mirrors the backend default config). */
export function contentSourceTier(source: string | null | undefined): "trusted" | "untrusted" | "unknown" {
  const s = source ?? "user_prompt"
  if (UNTRUSTED_CONTENT_SOURCES.has(s)) return "untrusted"
  if (TRUSTED_CONTENT_SOURCES.has(s))   return "trusted"
  return "unknown"
}

/** True for agent-pulled content (the indirect prompt-injection surface). */
export function isUntrustedSource(source: string | null | undefined): boolean {
  return contentSourceTier(source) === "untrusted"
}

// --- Primary reason (why the decision was made) ------------------------------
export const PRIMARY_REASON_LABELS: Record<string, string> = {
  RULE_DETECTOR:            "Rule detector",
  ML_DETECTOR:              "ML classifier",
  LLM_DETECTOR:             "LLM semantic analysis",
  PII_GUARDRAIL_BLOCK:      "PII guardrail - blocked",
  PII_GUARDRAIL_SANITIZE:   "PII guardrail - sanitized",
  TOXICITY_GUARDRAIL_BLOCK: "Toxicity guardrail - blocked",
  NO_THREAT_DETECTED:       "No threat detected",
  SYSTEM_ERROR:             "System error",
}

/** Human phrase for a primary_reason enum; falls back to the raw value. */
export function primaryReasonLabel(reason: string | null | undefined): string {
  if (!reason) return "--"
  return PRIMARY_REASON_LABELS[reason] ?? reason
}
