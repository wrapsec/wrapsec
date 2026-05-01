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
const SDK_VERSION      = "0.1.0"

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
          // retry ${attempt + 1}/${total - 1} — debug logging intentionally omitted
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
    "x-api-key":       apiKey,
    "Content-Type":    "application/json",
    "User-Agent":      `wrapsec-node/${SDK_VERSION}`,
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
  const errorMsg = (responseData as any)?.error?.message ?? ""

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
      "Endpoint not found. Check your baseUrl.",
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
    out[toCamel(k)] = v
  }
  return out
}

// ── ScanResult factory ─────────────────────────────────────────────────────

const VALID_DECISIONS = new Set(["ALLOW", "BLOCK", "SANITIZE"])

function makeScanResult(data: Record<string, unknown>): ScanResult {
  const d        = camelizeKeys(data)
  const decision = String(d["decision"] ?? "")
  if (!VALID_DECISIONS.has(decision)) {
    throw new WrapSecError(
      `Unexpected decision value from API: ${JSON.stringify(decision).slice(0, 50)}`
    )
  }
  const result = {
    decision,
    primaryReason:  String(d["primaryReason"]  ?? ""),
    confidence:     Number(d["confidence"]     ?? 0),
    confidenceBand: String(d["confidenceBand"] ?? "LOW"),
    traceId:        String(d["traceId"]        ?? ""),
    threats:        (d["threats"] as string[]) ?? [],
    latencyMs:      Number(
      d["latencyMs"] ??
      (d["processing"] as any)?.["latency_ms"] ??
      0
    ),
    sanitizedInput: d["sanitizedInput"] as string | undefined,
  }

  return {
    ...result,
    get isBlocked():     boolean { return result.decision === "BLOCK" },
    get isSanitized():   boolean { return result.decision === "SANITIZE" },
    get isAllowed():     boolean { return result.decision === "ALLOW" },
    get isSystemError(): boolean { return result.primaryReason === "SYSTEM_ERROR" },
  }
}

function makeAuditLog(data: Record<string, unknown>): AuditLog {
  const d = camelizeKeys(data)
  return {
    traceId:        String(d["traceId"]       ?? ""),
    decision:       String(d["decision"]      ?? ""),
    primaryReason:  String(d["primaryReason"] ?? ""),
    confidence:     Number(d["confidence"]    ?? d["riskScore"] ?? 0),
    confidenceBand: String(d["confidenceBand"] ?? ""),
    threats:        (d["threats"] as string[]) ?? [],
    latencyMs:      Number(d["latencyMs"]     ?? 0),
    inputLength:    Number(d["inputLength"]   ?? 0),
    keyId:          (d["keyId"]   as string)  ?? null,
    deptId:         (d["deptId"]  as string)  ?? null,
    appId:          (d["appId"]   as string)  ?? null,
    userId:         (d["userId"]  as string)  ?? null,
    source:         (d["source"]  as string)  ?? null,
    createdAt:      String(d["timestamp"] ?? d["createdAt"] ?? ""),
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
    const apiKey  = this.requireApiKey()
    const headers = buildHeaders(apiKey)
    const url     = this.url(path)

    return withRetry(
      () => executeRequest(method, url, headers, timeout, body, params),
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
    const { mode = "fast", user = "sdk-nodejs", timeout } = options

    if (!text || typeof text !== "string") {
      throw new WrapSecError("text must be a non-empty string")
    }
    if (Buffer.byteLength(text, "utf8") > 64 * 1024) {
      throw new WrapSecError("Input exceeds maximum size of 64KB")
    }
    if (timeout !== undefined && (typeof timeout !== "number" || timeout < 1 || !Number.isFinite(timeout))) {
      throw new WrapSecError("timeout must be a positive finite number")
    }

    const t    = this.resolveTimeout(timeout)
    const data = await this.request("POST", "/ai/request", t, {
      input:          text,
      detection_mode: mode,
      metadata:       { source: "wrapsec-node/0.1.0", user_id: user },
    })

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
    const { decision, reason, fromDate, toDate, limit = 20, timeout } = options
    const params: Record<string, string> = {
      limit: String(Math.min(limit, 100)),
    }
    if (decision) params["decision"]       = decision
    if (reason)   params["primary_reason"] = reason
    if (fromDate) params["from"]           = fromDate
    if (toDate)   params["to"]             = toDate

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
    const t    = this.resolveTimeout(timeout)
    const data = await this.request(
      "GET", "/audit/logs", t, undefined,
      { trace_id: traceId, limit: "1" },
    ) as any
    if (!traceId || typeof traceId !== "string" || traceId.trim().length === 0) {
      throw new WrapSecError("traceId must be a non-empty string")
    }
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
   * Uses a fixed 5s timeout — not configurable.
   *
   * Spec: Section 13.2 (ping)
   */
  async healthLive(): Promise<boolean> {
    try {
      const resp = await fetch(`${this._baseUrl}/health/live`, {
        signal: AbortSignal.timeout(5000),
      })
      return resp.ok
    } catch {
      return false
    }
  }

  /**
   * Check full service health (/health/ready). Auth required.
   * Fixed 5s timeout.
   *
   * Spec: Section 13.2 (doctor)
   */
  async healthReady(): Promise<Record<string, unknown>> {
    const apiKey  = this.requireApiKey()
    const headers = buildHeaders(apiKey)
    return executeRequest("GET", `${this._baseUrl}/health/ready`, headers, 5) as any
  }
}
