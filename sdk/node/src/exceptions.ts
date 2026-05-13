// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * WrapSec exception hierarchy — mirrors Python SDK exactly.
 *
 * Spec reference: Section 8 (SDK Error Mapping), Section 4 (Public API Surface)
 */

export class WrapSecError extends Error {
  readonly statusCode: number | undefined
  readonly response:   unknown

  constructor(
    message:    string,
    statusCode?: number,
    response?:  unknown,
  ) {
    super(message)
    this.name       = "WrapSecError"
    this.statusCode = statusCode
    this.response   = response
    // Restore prototype chain (required for instanceof in TypeScript)
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

/**
 * Raised on HTTP 401 (invalid/revoked key) or 403 (insufficient permissions).
 * Never retried — auth errors are permanent.
 *
 * Spec: Section 8, Section 15
 */
export class WrapSecAuthError extends WrapSecError {
  constructor(message: string, statusCode?: number, response?: unknown) {
    super(message, statusCode, response)
    this.name = "WrapSecAuthError"
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

/**
 * Raised on HTTP 429 (rate limit exceeded).
 * Never retried — retrying worsens the situation.
 *
 * Spec: Section 8, Section 9
 */
export class WrapSecRateLimitError extends WrapSecError {
  constructor(message: string, statusCode?: number, response?: unknown) {
    super(message, statusCode, response)
    this.name = "WrapSecRateLimitError"
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

/**
 * Raised on HTTP 5xx, timeout, connection error, or invalid JSON response.
 * Retried up to 3 times with exponential backoff before being raised.
 *
 * Spec: Section 8, Section 9
 */
export class WrapSecSystemError extends WrapSecError {
  constructor(message: string, statusCode?: number, response?: unknown) {
    super(message, statusCode, response)
    this.name = "WrapSecSystemError"
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

/**
 * Available for callers who prefer exception-based flow for BLOCK decisions.
 *
 * IMPORTANT: The SDK never raises this automatically.
 * client.scan() always returns ScanResult — callers check result.decision.
 *
 * Spec: Section 8
 */
export class WrapSecBlockError extends WrapSecError {
  readonly result: unknown

  constructor(result: unknown) {
    // #5 — sanitize API data before including in error message
    // primaryReason valid values are UPPER_SNAKE_CASE only (RULE_DETECTOR etc.)
    // traceId valid values are req_ prefix + alphanumeric only
    const rawReason  = String((result as any)?.primaryReason ?? "unknown")
    const rawTraceId = String((result as any)?.traceId       ?? "unknown")
    const reason     = rawReason.slice(0, 64).replace(/[^A-Z0-9_]/g, "")  // UPPER_SNAKE_CASE only
    const traceId    = rawTraceId.slice(0, 64).replace(/[^a-zA-Z0-9_-]/g, "") // alphanumeric + _ and -
    super(
      `Input blocked by WrapSec security policy (reason: ${reason}, trace: ${traceId})`
    )
    this.name   = "WrapSecBlockError"
    this.result = result
    Object.setPrototypeOf(this, new.target.prototype)
  }
}
