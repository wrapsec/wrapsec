// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * WrapSec TypeScript interfaces.
 *
 * All fields are camelCase — SDK transforms snake_case API responses.
 *
 * Field mapping (API → Node SDK):
 *   decision        → decision
 *   primary_reason  → primaryReason
 *   confidence      → confidence
 *   confidence_band → confidenceBand
 *   trace_id        → traceId
 *   sanitized_input → sanitizedInput
 *   latency_ms      → latencyMs
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
  /** Certainty of decision (0.0–1.0). Agreement between detectors, not probability. */
  confidence:      number
  /** "HIGH" (≥0.7) | "MEDIUM" (≥0.4) | "LOW" (<0.4) */
  confidenceBand:  string
  /** Unique request identifier for debugging and audit */
  traceId:         string
  /** Detected threat categories */
  threats:         string[]
  /** Detection latency in ms (scan-only) or end-to-end latency (proxy) */
  latencyMs:       number
  /** Redacted input. Only present when decision === "SANITIZE" */
  sanitizedInput?: string

  // Convenience properties
  readonly isBlocked:     boolean
  readonly isSanitized:   boolean
  readonly isAllowed:     boolean
  readonly isSystemError: boolean
}

// ── Audit log ──────────────────────────────────────────────────────────────

export interface AuditLog {
  traceId:       string
  decision:      string
  primaryReason: string
  confidence:    number
  confidenceBand:string
  threats:       string[]
  latencyMs:     number
  inputLength:   number
  keyId:         string | null
  deptId:        string | null
  appId:         string | null
  userId:        string | null
  source:        string | null
  createdAt:     string
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
  mode?:    "fast" | "full"
  /** User ID for audit attribution. Default: "sdk" */
  user?:    string
  /** Per-request timeout in seconds. Overrides client default. */
  timeout?: number
}

// ── audit list options ─────────────────────────────────────────────────────

export interface AuditListOptions {
  decision?:  "ALLOW" | "BLOCK" | "SANITIZE"
  reason?:    string
  fromDate?:  string
  toDate?:    string
  limit?:     number
  offset?:    number
  timeout?:   number
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
