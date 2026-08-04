// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * WrapSec TypeScript interfaces.
 *
 * All fields are camelCase — SDK transforms snake_case API responses.
 *
 * Field mapping (API → Node SDK):
 *   decision         → decision
 *   primary_reason   → primaryReason
 *   risk_score       → riskScore
 *   confidence       → confidence
 *   confidence_band  → confidenceBand
 *   trace_id         → traceId
 *   sanitized_input  → sanitizedInput
 *   latency_ms       → latencyMs
 *   execution_mode   → executionMode
 *
 * Spec reference: Section 5 (Field Naming Convention)
 */

// ── Client config ──────────────────────────────────────────────────────────

export interface WrapSecConfig {
  /** WrapSec API key (wsk_live_... or wsk_trial_...). Falls back to WRAPSEC_API_KEY env var. */
  apiKey?:  string
  /** WrapSec API base URL. Defaults to http://localhost:8000 (dev only). Always set in prod. */
  baseUrl?: string
  /** Default request timeout in seconds (min 1, default 30). Override per-call. */
  timeout?: number
}

// ── Scan result ────────────────────────────────────────────────────────────

export interface ScanResult {
  /** "ALLOW" | "BLOCK" | "SANITIZE" */
  decision:        string
  /** Which detector or guardrail triggered the decision */
  primaryReason:   string
  /** Overall risk level (0.0–1.0) — threshold used for BLOCK/SANITIZE/ALLOW decision */
  riskScore:       number
  /** Detection model certainty (0.0–1.0) — distinct from riskScore */
  confidence:      number
  /** "HIGH" (≥0.7) | "MEDIUM" (≥0.4) | "LOW" (<0.4) */
  confidenceBand:  string
  /** Unique request identifier for debugging and audit */
  traceId:         string
  /** Detected threat categories */
  threats:         string[]
  /** Detection latency (scan_only) or end-to-end latency (proxy) in ms */
  latencyMs:       number
  /** "scan_only" (default) or "proxy" */
  executionMode:   string
  /** True when input was sanitized (PII redacted). Same as decision === "SANITIZE" */
  sanitizationApplied: boolean
  /** Redacted input. Only present when decision === "SANITIZE" */
  sanitizedInput?: string
  /** LLM output. Only present when executionMode === "proxy" */
  output?:         string
  /**
   * v1.7.0 Security Assessment: the always-present structured verdict --
   * decision, reasons, threats, confidence, and per-layer contributions.
   */
  assessment?:     Record<string, unknown>

  // Convenience properties
  readonly isBlocked:     boolean
  readonly isSanitized:   boolean
  readonly isAllowed:     boolean
  readonly isSystemError: boolean
  readonly isProxy:       boolean
}

// ── Audit log ──────────────────────────────────────────────────────────────

export interface AuditLog {
  // Core identity
  traceId:             string
  createdAt:           string

  // Decision
  decision:            string
  primaryReason:       string
  riskScore:           number
  confidence:          number
  confidenceBand:      string
  threats:             string[]
  severity:            string | null

  // Performance
  latencyMs:           number
  inputLength:         number

  // Attribution
  keyId:               string | null
  deptId:              string | null
  deptName:            string | null
  appId:               string | null
  appName:             string | null
  userId:              string | null
  source:              string | null
  ipAddress:           string | null
  tenantId:            string | null
  attributionVerified: boolean

  // Processing metadata
  detectionMode:       string | null
  executionMode:       string | null
  policySource:        string | null
  inputHash:           string | null

  // Proxy mode — null for scan_only requests
  outputDecision:      string | null
  provider:            string | null
  model:               string | null

  // ML detection metadata
  modelVersion:        string | null
}

// ── Audit stats ────────────────────────────────────────────────────────────

export interface AuditStats {
  totalRequests:  number
  blockCount:     number
  sanitizeCount:  number
  allowCount:     number
  blockRate:      number
  avgLatencyMs:   number
  p95LatencyMs:   number
  topThreats:     Array<{ category: string; count: number }>
  severityCounts: {
    CRITICAL: number
    HIGH:     number
    MEDIUM:   number
    LOW:      number
  }
}

// ── scan() options ─────────────────────────────────────────────────────────

export interface ScanOptions {
  /** "fast" (default) or "full" (adds LLM analysis, ~100-500ms extra) */
  mode?:           "fast" | "full"
  /** "scan_only" (default) or "proxy" (scan + forward to LLM provider) */
  executionMode?:  "scan_only" | "proxy"
  /** LLM model identifier — required when executionMode is "proxy" */
  model?:          string
  /** User ID for audit attribution. Default: "sdk" */
  user?:           string
  /** Per-request timeout in seconds. Overrides client default. */
  timeout?:        number
  /**
   * Opaque conversation identifier grouping related scans.
   * Max 200 chars, [A-Za-z0-9_.:-] only. Do NOT include PII
   * (name, email, phone) - use a UUID or hash.
   */
  sessionId?:      string
  /** Zero-based index of this turn within sessionId (0-10000). */
  turnIndex?:      number
  /**
   * Opaque identifier for one agent execution (may span multiple
   * scans, tool calls, LLM calls). Matches LangSmith / OpenAI
   * Assistants run_id semantics. Max 200 chars.
   */
  runId?:          string
  /**
   * Trust-boundary provenance of the scanned text: "user_prompt" (default),
   * "tool_output", "retrieved_document", or "external_content". Untrusted
   * origins mark agent-pulled content (indirect prompt-injection surface).
   * Labels and audits only; never relaxes detection.
   */
  inputSource?:    string
}

// ── audit list options ─────────────────────────────────────────────────────

export interface AuditListOptions {
  decision?:       "ALLOW" | "BLOCK" | "SANITIZE"
  reason?:         string
  executionMode?:  "scan_only" | "proxy"
  fromDate?:       string
  toDate?:         string
  limit?:          number
  offset?:         number
  timeout?:        number
}

// ── audit export options ───────────────────────────────────────────────────

export interface AuditExportOptions {
  decision?:        "ALLOW" | "BLOCK" | "SANITIZE"
  primaryReason?:   string
  confidenceBand?:  "HIGH" | "MEDIUM" | "LOW"
  fromDate?:        string
  toDate?:          string
  deptId?:          string
  appId?:           string
  limit?:           number
  timeout?:         number
}

// ── Express middleware options ─────────────────────────────────────────────

export interface ExpressMiddlewareOptions {
  /** WrapSec API key. Falls back to WRAPSEC_API_KEY env var. */
  apiKey?:   string
  /** WrapSec API base URL. */
  baseUrl?:  string
  /** Request timeout in seconds. Default: 30. */
  timeout?:  number
  /** Called when input is blocked. Default: 403 JSON response. */
  onBlock?:  (req: unknown, res: unknown, result: ScanResult) => void
  /** Detection mode. Default: "fast". */
  mode?:     "fast" | "full"
  /** Input field to scan. Default: reads req.body as string or req.body.input */
  inputKey?: string
}
