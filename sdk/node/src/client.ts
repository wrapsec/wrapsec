// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * WrapSec Node.js client.
 *
 * Responsibilities:
 *   - API interaction only: HTTP calls, response parsing, returning typed results
 *   - camelCase field transformation of all API responses
 *   - Timeout resolution (method → client → env → fallback)
 *   - Retry via withRetry() for transient failures
 *
 * Spec reference: Section 4, Section 5 (camelCase), Section 7 (Timeout), Section 9 (Retry)
 */

import {
  WrapSecAuthError,
  WrapSecError,
  WrapSecRateLimitError,
  WrapSecSystemError,
} from "./exceptions"
import type {
  AuditExportOptions,
  AuditListOptions,
  AuditLog,
  AuditStats,
  ScanOptions,
  ScanResult,
  WrapSecConfig,
} from "./types"

// ── Constants ──────────────────────────────────────────────────────────────

/** Single constant — the ONLY place /v1 is defined in this SDK. Spec §6.5 */
const BASE_PATH        = "/v1"
const DEFAULT_BASE_URL = "http://localhost:8000"
const SDK_VERSION: string = (() => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return (require("../package.json") as { version: string }).version
  } catch {
    return "1.0.0"
  }
})()

// ── Retry ──────────────────────────────────────────────────────────────────

/** Backoff delays in ms between attempts. Matches Python SDK schedule. Spec §9 */
const BACKOFF_SCHEDULE = [0, 1000, 2000]

async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

async function withRetry<T>(
  fn:        () => Promise<T>,
  operation: string = "request",
): Promise<T> {
  let lastError: WrapSecSystemError | undefined

  for (let i = 0; i < BACKOFF_SCHEDULE.length; i++) {
    const delay = BACKOFF_SCHEDULE[i]
    if (delay > 0) await sleep(delay)

    try {
      return await fn()
    } catch (err) {
      if (err instanceof WrapSecSystemError) {
        lastError = err
        const attempt = i + 1
        const total   = BACKOFF_SCHEDULE.length
        if (attempt < total) {
          // attempt ${attempt}/${total} failed — will retry after backoff
        }
        // Continue to next attempt
      } else {
        // Not retryable — auth, rate limit, validation errors propagate immediately
        throw err
      }
    }
  }

  throw lastError ?? new WrapSecSystemError(
    `Operation failed after ${BACKOFF_SCHEDULE.length} attempts`
  )
}

// ── HTTP layer ─────────────────────────────────────────────────────────────

function buildHeaders(apiKey: string): Record<string, string> {
  return {
    "x-api-key":        apiKey,
    "Content-Type":     "application/json",
    "User-Agent":       `wrapsec-node/${SDK_VERSION}`,
    "Idempotency-Key":  crypto.randomUUID(),  // #1 match Python SDK behavior
  }
}

function resolveTimeout(
  methodTimeout?: number,
  clientTimeout?: number,
  fallback:       number = 30,
): number {
  // Strict is not None chain — never use falsy check (timeout=0 would hang)
  // Spec: Section 7
  const t = methodTimeout !== undefined ? methodTimeout
          : clientTimeout !== undefined ? clientTimeout
          : fallback
  if (t < 1) throw new Error(`timeout must be at least 1 second, got ${t}`)
  return t
}

function mapResponseError(
  statusCode:   number,
  responseData: unknown,
): WrapSecError {
  // Prefer structured {"error": {"message": "..."}} — fall back to FastAPI's {"detail": "..."}
  const errorMsg: string =
    (responseData as any)?.error?.message ??
    (typeof (responseData as any)?.detail === "string" ? (responseData as any).detail : "") ??
    ""

  if (statusCode === 401) {
    return new WrapSecAuthError(
      "Invalid or revoked API key.",
      statusCode,
      responseData,
    )
  }
  if (statusCode === 403) {
    return new WrapSecAuthError(
      "Permission denied.",
      statusCode,
      responseData,
    )
  }
  if (statusCode === 404) {
    return new WrapSecError(
      errorMsg || "Not found. Check your baseUrl or run wrapsec doctor.",
      statusCode,
      responseData,
    )
  }
  if (statusCode === 413) {
    return new WrapSecError(
      "Input too large. Max payload is 64KB.",
      statusCode,
      responseData,
    )
  }
  if (statusCode === 422) {
    return new WrapSecError(
      errorMsg || "Request validation failed.",
      statusCode,
      responseData,
    )
  }
  if (statusCode === 429) {
    return new WrapSecRateLimitError(
      "Rate limit exceeded. Try again later.",
      statusCode,
      responseData,
    )
  }
  if (statusCode >= 500) {
    return new WrapSecSystemError(
      `Server error (${statusCode}). WrapSec API is experiencing issues.`,
      statusCode,
      responseData,
    )
  }
  return new WrapSecError(
    `Unexpected HTTP ${statusCode}: ${errorMsg}`,
    statusCode,
    responseData,
  )
}

async function executeRequest(
  method:  string,
  url:     string,
  headers: Record<string, string>,
  timeout: number,
  body?:   unknown,
  params?: Record<string, string>,
): Promise<unknown> {
  // Build URL with query params
  const fullUrl = new URL(url)
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) fullUrl.searchParams.set(k, v)
    }
  }

  const controller = new AbortController()
  const timer      = setTimeout(() => controller.abort(), timeout * 1000)

  try {
    const resp = await fetch(fullUrl.toString(), {
      method:  method.toUpperCase(),
      headers,
      body:    body !== undefined ? JSON.stringify(body) : undefined,
      signal:  controller.signal,
    })

    let responseData: unknown = null
    const contentType = resp.headers.get("content-type") ?? ""
    if (contentType.includes("application/json")) {
      try { responseData = await resp.json() } catch { /* fall through */ }
    }

    if (!resp.ok) {
      throw mapResponseError(resp.status, responseData)
    }

    return responseData ?? {}

  } catch (err) {
    if ((err as any)?.name === "AbortError") {
      throw new WrapSecSystemError(
        `Request timed out after ${timeout}s.`
      )
    }
    if (err instanceof WrapSecError) throw err
    // Network / connection errors
    throw new WrapSecSystemError(
      `Cannot reach WrapSec API. Check your network connection and baseUrl.`
    )
  } finally {
    clearTimeout(timer)
  }
}

// ── camelCase transformation ────────────────────────────────────────────────

function toCamel(s: string): string {
  return s.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
}

// Blocked keys — prevent prototype pollution from API responses
const BLOCKED_KEYS = new Set(["__proto__", "constructor", "prototype"])

function camelizeKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = Object.create(null)
  for (const [k, v] of Object.entries(obj)) {
    if (BLOCKED_KEYS.has(k)) continue   // #3 prototype pollution guard
    const camelKey = toCamel(k)
    if (Array.isArray(v)) {
      // Recurse into arrays of objects — e.g. top_threats: [{category, count}]
      out[camelKey] = v.map(item =>
        item !== null && typeof item === "object" && !Array.isArray(item)
          ? camelizeKeys(item as Record<string, unknown>)
          : item
      )
    } else if (v !== null && typeof v === "object") {
      out[camelKey] = camelizeKeys(v as Record<string, unknown>)
    } else {
      out[camelKey] = v
    }
  }
  return out
}

// ── ScanResult factory ─────────────────────────────────────────────────────

const VALID_DECISIONS = new Set(["ALLOW", "BLOCK", "SANITIZE"])

// Session/run identifier constraints mirror the API's Pydantic validators.
// Opaque strings only; charset [A-Za-z0-9_.:-]; max 200 chars.
const SESSION_ID_MAX_LEN = 200
const SESSION_ID_PATTERN = /^[A-Za-z0-9_.:\-]+$/
const TURN_INDEX_MAX     = 10000

function validateSessionId(value: string | undefined, field: string): string | undefined {
  if (value === undefined) return undefined
  if (typeof value !== "string") {
    throw new WrapSecError(`${field} must be a string, got ${typeof value}`)
  }
  if (value.length === 0) {
    throw new WrapSecError(`${field} must be non-empty; omit the field instead`)
  }
  if (value.length > SESSION_ID_MAX_LEN) {
    throw new WrapSecError(
      `${field} exceeds max length of ${SESSION_ID_MAX_LEN} chars (got ${value.length})`
    )
  }
  if (!SESSION_ID_PATTERN.test(value)) {
    throw new WrapSecError(
      `${field} contains disallowed characters; allowed: [A-Za-z0-9_.:-]`
    )
  }
  return value
}

function validateTurnIndex(value: number | undefined): number | undefined {
  if (value === undefined) return undefined
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new WrapSecError(`turnIndex must be an integer, got ${typeof value}`)
  }
  if (value < 0 || value > TURN_INDEX_MAX) {
    throw new WrapSecError(`turnIndex must be in [0, ${TURN_INDEX_MAX}], got ${value}`)
  }
  return value
}

const VALID_INPUT_SOURCES = [
  "user_prompt", "tool_output", "retrieved_document", "external_content",
] as const

function validateInputSource(value: string): string {
  if (!VALID_INPUT_SOURCES.includes(value as any)) {
    throw new WrapSecError(
      `inputSource must be one of ${JSON.stringify(VALID_INPUT_SOURCES)}, got ${JSON.stringify(value)}`
    )
  }
  return value
}

function makeScanResult(data: Record<string, unknown>): ScanResult {
  const d        = camelizeKeys(data)
  const decision = String(d["decision"] ?? "")
  if (!VALID_DECISIONS.has(decision)) {
    throw new WrapSecError(
      `Unexpected decision value from API: ${JSON.stringify(decision).slice(0, 50)}`
    )
  }
  // processing is a nested object — camelizeKeys recurses into it, so keys are camelCase
  const processing = d["processing"] as Record<string, unknown> | undefined

  const result = {
    decision,
    primaryReason:  String(d["primaryReason"]  ?? ""),
    riskScore:      Number(d["riskScore"]       ?? 0),
    confidence:     Number(d["confidence"]      ?? 0),
    confidenceBand: String(d["confidenceBand"]  ?? "LOW"),
    traceId:        String(d["traceId"]         ?? ""),
    threats:        Array.isArray(d["threats"]) ? (d["threats"] as string[]) : [],
    // latency_ms is nested in processing in the scan response (not top-level)
    latencyMs:      Number(processing?.["latencyMs"] ?? d["latencyMs"] ?? 0),
    executionMode:        String(processing?.["executionMode"] ?? d["executionMode"] ?? "scan_only"),
    sanitizationApplied:  Boolean(d["sanitizationApplied"] ?? false),
    sanitizedInput:       d["sanitizedInput"] != null ? String(d["sanitizedInput"]) : undefined,
    output:               d["output"] != null ? String(d["output"]) : undefined,
  }

  return {
    ...result,
    get isBlocked():     boolean { return result.decision === "BLOCK" },
    get isSanitized():   boolean { return result.decision === "SANITIZE" },
    get isAllowed():     boolean { return result.decision === "ALLOW" },
    get isSystemError(): boolean { return result.primaryReason === "SYSTEM_ERROR" },
    get isProxy():       boolean { return result.executionMode === "proxy" },
  }
}

function makeAuditLog(data: Record<string, unknown>): AuditLog {
  const d = camelizeKeys(data)
  return {
    // Core identity
    traceId:             String(d["traceId"]    ?? ""),
    // API returns "timestamp" or "created_at"; both are camelized
    createdAt:           String(d["timestamp"]  ?? d["createdAt"] ?? ""),

    // Decision — risk_score and confidence are separate; never substitute one for the other
    decision:            String(d["decision"]      ?? ""),
    primaryReason:       String(d["primaryReason"] ?? ""),
    riskScore:           Number(d["riskScore"]     ?? 0),
    confidence:          Number(d["confidence"]    ?? 0),
    confidenceBand:      String(d["confidenceBand"] ?? ""),
    threats:             Array.isArray(d["threats"]) ? (d["threats"] as string[]) : [],
    severity:            d["severity"] != null ? String(d["severity"]) : null,

    // Performance
    latencyMs:           Number(d["latencyMs"]   ?? 0),
    inputLength:         Number(d["inputLength"] ?? 0),

    // Attribution
    keyId:               d["keyId"]    != null ? String(d["keyId"])    : null,
    deptId:              d["deptId"]   != null ? String(d["deptId"])   : null,
    deptName:            d["deptName"] != null ? String(d["deptName"]) : null,
    appId:               d["appId"]    != null ? String(d["appId"])    : null,
    appName:             d["appName"]  != null ? String(d["appName"])  : null,
    userId:              d["userId"]   != null ? String(d["userId"])   : null,
    source:              d["source"]   != null ? String(d["source"])   : null,
    ipAddress:           d["ipAddress"]  != null ? String(d["ipAddress"])  : null,
    tenantId:            d["tenantId"]   != null ? String(d["tenantId"])   : null,
    attributionVerified: Boolean(d["attributionVerified"] ?? false),

    // Processing metadata
    detectionMode:       d["detectionMode"] != null ? String(d["detectionMode"]) : null,
    executionMode:       d["executionMode"] != null ? String(d["executionMode"]) : null,
    policySource:        d["policySource"]  != null ? String(d["policySource"])  : null,
    inputHash:           d["inputHash"]     != null ? String(d["inputHash"])     : null,

    // Proxy mode
    outputDecision:      d["outputDecision"] != null ? String(d["outputDecision"]) : null,
    provider:            d["provider"]       != null ? String(d["provider"])       : null,
    model:               d["model"]          != null ? String(d["model"])          : null,

    // ML detection metadata
    modelVersion:        d["model_version"]  != null ? String(d["model_version"])  : null,
  }
}

function makeAuditStats(data: Record<string, unknown>): AuditStats {
  const d     = camelizeKeys(data)
  const total = Number(d["totalRequests"] ?? 0)
  const br    = Number(d["blockRate"]     ?? 0)
  const sr    = Number(d["sanitizeRate"]  ?? 0)
  const ar    = Number(d["allowRate"]     ?? 0)
  return {
    totalRequests:  total,
    blockCount:     Number(d["blockCount"]    ?? Math.round(total * br)),
    sanitizeCount:  Number(d["sanitizeCount"] ?? Math.round(total * sr)),
    allowCount:     Number(d["allowCount"]    ?? Math.round(total * ar)),
    blockRate:      br,
    avgLatencyMs:   Number(d["avgLatencyMs"]  ?? 0),
    p95LatencyMs:   Number(d["p95LatencyMs"]  ?? 0),
    topThreats:     (d["topThreats"] as any[]) ?? [],
    severityCounts: (d["severityCounts"] as any) ?? {
      CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0,
    },
  }
}

// ── WrapSec client class ───────────────────────────────────────────────────

export class WrapSec {
  private readonly _apiKey:   string | undefined
  private readonly _baseUrl:  string
  private readonly _timeout:  number | undefined

  constructor(config: WrapSecConfig = {}) {
    // Resolve api_key: constructor arg → WRAPSEC_API_KEY env var
    this._apiKey  = config.apiKey ?? process.env["WRAPSEC_API_KEY"]

    // Resolve base_url: constructor arg → WRAPSEC_BASE_URL env var → default
    this._baseUrl = (
      (config.baseUrl ?? "").replace(/\/$/, "") ||
      (process.env["WRAPSEC_BASE_URL"] ?? "").replace(/\/$/, "") ||
      DEFAULT_BASE_URL
    )

    if (config.timeout !== undefined && config.timeout < 1) {
      throw new Error(`timeout must be at least 1 second, got ${config.timeout}`)
    }
    this._timeout = config.timeout

    // #10 — warn on obviously invalid key formats at construction time
    if (this._apiKey && typeof this._apiKey === "string") {
      const k = this._apiKey
      if (!k.startsWith("wsk_live_") && !k.startsWith("wsk_trial_") && k !== "wrapsec_admin_key") {
        // Not an error — admin keys and custom setups may differ. Log only.
        // Do not throw — constructor must not fail on valid non-standard keys.
      }
    }
  }

  private requireApiKey(): string {
    if (!this._apiKey) {
      throw new WrapSecAuthError(
        "No API key configured. Set apiKey in constructor or WRAPSEC_API_KEY env var."
      )
    }
    return this._apiKey
  }

  private url(path: string): string {
    return `${this._baseUrl}${BASE_PATH}${path}`
  }

  private resolveTimeout(methodTimeout?: number): number {
    return resolveTimeout(methodTimeout, this._timeout)
  }

  private async request(
    method:  string,
    path:    string,
    timeout: number,
    body?:   unknown,
    params?: Record<string, string>,
  ): Promise<unknown> {
    const apiKey = this.requireApiKey()
    const url    = this.url(path)

    return withRetry(
      () => executeRequest(method, url, buildHeaders(apiKey), timeout, body, params),
      `${method.toUpperCase()} ${path}`,
    )
  }

  // ── Public API ─────────────────────────────────────────────────────────

  /**
   * Scan a single input for security risks.
   *
   * BLOCK is not thrown — check result.decision.
   * Spec: Section 4, Section 8
   */
  async scan(text: string, options: ScanOptions = {}): Promise<ScanResult> {
    const {
      mode = "fast",
      executionMode = "scan_only",
      model,
      user = "sdk",
      timeout,
      sessionId,
      turnIndex,
      runId,
      inputSource = "user_prompt",
    } = options

    if (!text || typeof text !== "string") {
      throw new WrapSecError("text must be a non-empty string")
    }
    if (Buffer.byteLength(text, "utf8") > 64 * 1024) {
      throw new WrapSecError("Input exceeds maximum size of 64KB")
    }
    if (timeout !== undefined && (typeof timeout !== "number" || timeout < 1 || !Number.isFinite(timeout))) {
      throw new WrapSecError("timeout must be a positive finite number")
    }
    // Runtime mode validation — TypeScript types are not runtime guards
    const _VALID_MODES = ["fast", "full"] as const
    if (!_VALID_MODES.includes(mode as any)) {
      throw new WrapSecError(
        `mode must be one of ${JSON.stringify(_VALID_MODES)}, got ${JSON.stringify(mode)}`
      )
    }
    const _VALID_EXECUTION_MODES = ["scan_only", "proxy"] as const
    if (!_VALID_EXECUTION_MODES.includes(executionMode as any)) {
      throw new WrapSecError(
        `executionMode must be one of ${JSON.stringify(_VALID_EXECUTION_MODES)}, got ${JSON.stringify(executionMode)}`
      )
    }
    if (executionMode === "proxy" && !model) {
      throw new WrapSecError("model is required when executionMode is 'proxy'")
    }

    const validSessionId   = validateSessionId(sessionId, "sessionId")
    const validRunId       = validateSessionId(runId, "runId")
    const validTurnIndex   = validateTurnIndex(turnIndex)
    const validInputSource = validateInputSource(inputSource)

    const t    = this.resolveTimeout(timeout)
    const body: Record<string, unknown> = {
      input:          text,
      detection_mode: mode,
      execution_mode: executionMode,
      metadata:       { source: `wrapsec-node/${SDK_VERSION}`, user_id: user },
    }
    if (model)          body["model"]      = model
    if (validSessionId) body["session_id"] = validSessionId
    if (validRunId)     body["run_id"]     = validRunId
    if (validTurnIndex !== undefined) body["turn_index"] = validTurnIndex
    body["input_source"] = validInputSource

    const data = await this.request("POST", "/ai/request", t, body)
    return makeScanResult(data as Record<string, unknown>)
  }

  /**
   * Scan multiple inputs. Returns results in the same order as inputs.
   *
   * Spec: Section 13.1 (batch)
   */
  async batch(
    texts:    string[],
    options:  ScanOptions & { delayMs?: number } = {},
  ): Promise<ScanResult[]> {
    const { delayMs = 0, ...scanOptions } = options
    if (typeof delayMs !== "number" || delayMs < 0 || !Number.isFinite(delayMs)) {
      throw new WrapSecError("delayMs must be a non-negative finite number")
    }
    const results: ScanResult[] = []

    for (let i = 0; i < texts.length; i++) {
      if (delayMs > 0 && i > 0) await sleep(delayMs)
      results.push(await this.scan(texts[i], scanOptions))
    }

    return results
  }

  /**
   * List recent audit log entries. Read-only.
   *
   * Spec: Section 13.2 (audit list)
   */
  async auditList(options: AuditListOptions = {}): Promise<AuditLog[]> {
    const { decision, reason, executionMode, fromDate, toDate, limit = 20, offset = 0, timeout } = options
    const params: Record<string, string> = {
      limit:  String(Math.min(limit, 100)),
      offset: String(Math.max(offset, 0)),
    }
    if (decision)       params["decision"]        = decision
    if (reason)         params["primary_reason"]  = reason
    if (executionMode)  params["execution_mode"]  = executionMode
    if (fromDate)       params["from"]            = fromDate
    if (toDate)         params["to"]              = toDate

    const t    = this.resolveTimeout(timeout)
    const data = await this.request("GET", "/audit/logs", t, undefined, params) as any
    const items = data?.items ?? data?.logs ?? []
    return items.map((item: Record<string, unknown>) => makeAuditLog(item))
  }

  /**
   * Retrieve a single audit log entry by trace ID.
   *
   * Spec: Section 13.2 (audit get)
   */
  async auditGet(traceId: string, timeout?: number): Promise<AuditLog> {
    if (!traceId || typeof traceId !== "string" || traceId.trim().length === 0) {
      throw new WrapSecError("traceId must be a non-empty string")
    }
    const t    = this.resolveTimeout(timeout)
    const data = await this.request(
      "GET", "/audit/logs", t, undefined,
      { trace_id: traceId, limit: "1" },
    ) as any
    const items = data?.items ?? data?.logs ?? []
    if (!items.length) {
      throw new WrapSecError(`Audit record not found: ${traceId}`)
    }
    return makeAuditLog(items[0])
  }

  /**
   * Retrieve aggregated audit statistics. Read-only.
   *
   * Spec: Section 13.2 (audit stats)
   */
  async auditStats(options: { fromDate?: string; toDate?: string; timeout?: number } = {}): Promise<AuditStats> {
    const { fromDate, toDate, timeout } = options
    const params: Record<string, string> = {}
    if (fromDate) params["from"] = fromDate
    if (toDate)   params["to"]   = toDate

    const t    = this.resolveTimeout(timeout)
    const data = await this.request("GET", "/audit/stats", t, undefined, params)
    return makeAuditStats(data as Record<string, unknown>)
  }

  /**
   * Retrieve the full audit record for a single request by trace ID.
   * Includes proxy enrichment when executionMode is "proxy".
   * Scoped to the caller's dept/tenant — throws WrapSecError if out of scope.
   *
   * Returns a raw camelCased object (structure varies by executionMode).
   */
  async getRequest(traceId: string, timeout?: number): Promise<Record<string, unknown>> {
    if (!traceId || typeof traceId !== "string" || traceId.trim().length === 0) {
      throw new WrapSecError("traceId must be a non-empty string")
    }
    const t    = this.resolveTimeout(timeout)
    const data = await this.request("GET", `/ai/requests/${traceId}`, t)
    return camelizeKeys(data as Record<string, unknown>)
  }

  /**
   * Export audit logs as CSV (up to 10,000 rows). Returns a Buffer of CSV bytes.
   * Scope is bounded by the API key used.
   *
   *   const csv = await client.auditExport({ decision: "BLOCK" })
   *   fs.writeFileSync("audit.csv", csv)
   */
  async auditExport(options: AuditExportOptions = {}): Promise<Buffer> {
    const {
      decision, primaryReason, confidenceBand,
      fromDate, toDate, deptId, appId,
      limit = 1000, timeout,
    } = options

    const apiKey = this.requireApiKey()
    const params: Record<string, string> = {
      limit: String(Math.min(limit, 10000)),
    }
    if (decision)        params["decision"]         = decision
    if (primaryReason)   params["primary_reason"]   = primaryReason
    if (confidenceBand)  params["confidence_band"]  = confidenceBand
    if (fromDate)        params["from"]             = fromDate
    if (toDate)          params["to"]               = toDate
    if (deptId)          params["dept_id"]          = deptId
    if (appId)           params["app_id"]           = appId

    const t       = this.resolveTimeout(timeout)
    const fullUrl = new URL(this.url("/audit/export"))
    for (const [k, v] of Object.entries(params)) {
      fullUrl.searchParams.set(k, v)
    }

    const controller = new AbortController()
    const timer      = setTimeout(() => controller.abort(), t * 1000)

    try {
      const resp = await fetch(fullUrl.toString(), {
        method:  "GET",
        headers: buildHeaders(apiKey),
        signal:  controller.signal,
      })
      if (resp.ok) {
        return Buffer.from(await resp.arrayBuffer())
      }
      // Error path — attempt to parse JSON error body
      let responseData: unknown = null
      try { responseData = await resp.json() } catch { /* fall through */ }
      throw mapResponseError(resp.status, responseData)
    } catch (err) {
      if ((err as any)?.name === "AbortError") {
        throw new WrapSecSystemError(`Request timed out after ${t}s.`)
      }
      if (err instanceof WrapSecError) throw err
      throw new WrapSecSystemError("Cannot reach WrapSec API. Check your network connection and baseUrl.")
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Retrieve active gateway configuration. Read-only.
   * Returns raw object — structure varies by config source.
   *
   * Spec: Section 13.2 (settings get)
   */
  async settingsGet(timeout?: number): Promise<Record<string, unknown>> {
    const t = this.resolveTimeout(timeout)
    const [thresholds, layers, llm, rateLimit] = await Promise.all([
      this.request("GET", "/settings/thresholds", t),
      this.request("GET", "/settings/layers",     t),
      this.request("GET", "/settings/llm",        t),
      this.request("GET", "/settings/rate_limit", t),
    ])
    return { thresholds, layers, llm, rateLimit }
  }

  /**
   * List API keys visible to the current key. Read-only.
   * Does NOT return key secrets — never retrievable after creation.
   *
   * Spec: Section 13.2 (keys list)
   */
  async keysList(timeout?: number): Promise<unknown[]> {
    const t    = this.resolveTimeout(timeout)
    const data = await this.request("GET", "/keys", t) as any
    return data?.keys ?? []
  }

  /**
   * Check if the API is reachable (/health/live). No auth required.
   * Returns false on any error — never throws.
   *
   * Spec: Section 13.2 (ping)
   */
  async healthLive(timeout?: number): Promise<boolean> {
    const t = resolveTimeout(timeout, this._timeout, 5) * 1000
    try {
      const resp = await fetch(`${this._baseUrl}/health/live`, {
        signal: AbortSignal.timeout(t),
      })
      return resp.ok
    } catch {
      return false
    }
  }

  /**
   * Check full service health (/health/ready). Auth required.
   * Retried on transient failures via withRetry().
   *
   * Spec: Section 13.2 (doctor)
   */
  async healthReady(timeout?: number): Promise<Record<string, unknown>> {
    const apiKey = this.requireApiKey()
    const t      = resolveTimeout(timeout, this._timeout, 5)
    return withRetry(
      () => {
        const headers = buildHeaders(apiKey)
        return executeRequest("GET", `${this._baseUrl}/health/ready`, headers, t) as Promise<Record<string, unknown>>
      },
      "GET /health/ready",
    ) as Promise<Record<string, unknown>>
  }

  /**
   * Retrieve active gateway configuration (/health/config). Auth required.
   * Equivalent to Python SDK health_config().
   *
   * Spec: Section 13.2 (settings get)
   */
  async healthConfig(timeout?: number): Promise<Record<string, unknown>> {
    const apiKey = this.requireApiKey()
    const t      = resolveTimeout(timeout, this._timeout, 5)
    return withRetry(
      () => {
        const headers = buildHeaders(apiKey)
        return executeRequest("GET", `${this._baseUrl}/health/config`, headers, t) as Promise<Record<string, unknown>>
      },
      "GET /health/config",
    ) as Promise<Record<string, unknown>>
  }

  /**
   * Normalize text before scanning: collapse whitespace, strip leading/trailing
   * whitespace, and normalize Unicode to NFC.
   *
   * Equivalent to Python SDK normalize_text(). Pass the result to scan().
   */
  static normalizeText(text: string): string {
    if (typeof text !== "string") throw new WrapSecError("text must be a string")
    return text.normalize("NFC").replace(/\s+/g, " ").trim()
  }
}
