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
  /**
   * Version of the decision contract this verdict was produced under. Always
   * sent; a caller pinning behaviour reads it rather than inferring from shape.
   */
  decisionVersion: string
  /**
   * Admin-only detector diagnostics. The one field here that is genuinely
   * ABSENT rather than null when it does not apply -- returned only when an
   * admin key asked for it, so undefined means "not requested or not
   * permitted", not "no diagnostics".
   */
  debug?:          Record<string, unknown>

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

  /**
   * Agent correlation. Caller-supplied and always present in the body, though
   * null when the caller sent none; runId is the handle that reads a whole
   * multi-turn run back via GET /v1/agent-runs/{run_id}. Correlation only --
   * the gateway never treats any of the three as an authorization input.
   */
  runId:               string | null
  sessionId:           string | null
  turnIndex:           number | null

  /**
   * Tamper-evident chain. recordHash is this row's hash and prevHash links it
   * to the preceding one, which is null for the first row in a tenant's chain.
   * Exposed so a caller can verify the chain itself rather than having to trust
   * the response that carries it.
   */
  prevHash:            string | null
  recordHash:          string | null

  /** Declared provenance of the scanned input, e.g. "user_prompt". */
  inputSource:         string
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

  /**
   * The rates the API reports directly. blockRate was already exposed and these
   * two were not, though both were being read to derive their counts -- so a
   * caller could get the count and not the fraction it came from.
   */
  allowRate:      number
  sanitizeRate:   number
  /** Mean aggregate risk across matching requests, 0.0-1.0. */
  avgRisk:        number
  /** The window the figures cover, echoed from the query or defaulted. */
  periodFrom:     string
  periodTo:       string
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
   * "tool_output", "retrieved_document", "external_content", or
   * "agent_tool_call". Untrusted origins mark agent-pulled content (indirect
   * prompt-injection surface) and arguments a model composed for a tool call.
   * Labels and audits only; never relaxes detection.
   */
  inputSource?:    string
}

// --- Batch scan --------------------------------------------------------------

/** One input in a batch scan: a plain string, or an object with provenance/id. */
export interface BatchItem {
  /** The text to scan. `text` is accepted as an alias for `input`. */
  input?:       string
  text?:        string
  /** Trust-boundary provenance for this item. Defaults per method. */
  inputSource?: string
  /** Opaque caller reference echoed back on the matching result. */
  id?:          string
}

export interface BatchScanOptions {
  /** "fast" (default) or "full" (adds LLM analysis). */
  mode?:    "fast" | "full"
  /** Per-request timeout in seconds. Overrides client default. */
  timeout?: number
}

/** One item's outcome within a batch scan. */
export interface BatchItemResult {
  /** Caller-supplied reference echoed back (null if not given). */
  id:          string | null
  /** This item's own scan trace_id -- correlates to the audit trail. */
  traceId:     string
  /** "ALLOW" | "BLOCK" | "SANITIZE" */
  decision:    string
  /** Structured security assessment for this item. */
  assessment?: Record<string, unknown>
  readonly isBlocked:   boolean
  readonly isSanitized: boolean
  readonly isAllowed:   boolean
}

/** Result of a batch scan (POST /v1/ai/scan-batch). */
export interface BatchScanResult {
  /** Number of items scanned. */
  count:   number
  /** Aggregate: blocked/sanitized/allowed counts, highestRisk (+ item id), threats. */
  summary: Record<string, unknown>
  /** Per-item outcomes, in the same order as the inputs. */
  results: BatchItemResult[]
  /** The subset of results with decision === "BLOCK". */
  readonly blocked: BatchItemResult[]
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
