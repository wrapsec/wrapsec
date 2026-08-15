// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * Typed API error carrying the full WrapSec error envelope
 * ({code, severity, key, params, message, trace_id, invalid_params}) so the UI
 * can resolve a LOCALIZED message from the code's localization key rather than
 * displaying the backend's English convenience string. See useErrorMessage.
 */
export interface InvalidParam {
  field:   string
  code:    string
  key:     string
  params?: Record<string, unknown>
}

export class ApiError extends Error {
  status:        number
  code?:         string
  key?:          string
  params?:       Record<string, unknown>
  severity?:     string
  traceId?:      string
  invalidParams: InvalidParam[]

  constructor(init: {
    status:        number
    message:       string
    code?:         string
    key?:          string
    params?:       Record<string, unknown>
    severity?:     string
    traceId?:      string
    invalidParams?: InvalidParam[]
  }) {
    super(init.message)
    this.name          = "ApiError"
    this.status        = init.status
    this.code          = init.code
    this.key           = init.key
    this.params        = init.params
    this.severity      = init.severity
    this.traceId       = init.traceId
    this.invalidParams = init.invalidParams ?? []
  }
}

/**
 * Extract a display message from an unknown caught value. request() throws an
 * ApiError (which extends Error), so this returns the same string that `e.message`
 * on an `any`-typed catch produced -- it only replaces the unsafe `any` with a
 * narrowed `unknown`. Behavior is unchanged.
 */
export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** Build an ApiError from a response status + parsed JSON body (may be null). */
export function parseApiError(status: number, body: unknown): ApiError {
  const err = (body as { error?: Record<string, unknown> } | null)?.error ?? {}
  return new ApiError({
    status,
    message:       (err.message as string) || `HTTP ${status}`,
    code:          err.code as string | undefined,
    key:           err.key as string | undefined,
    params:        err.params as Record<string, unknown> | undefined,
    severity:      err.severity as string | undefined,
    traceId:       err.trace_id as string | undefined,
    invalidParams: (err.invalid_params as InvalidParam[] | undefined) ?? [],
  })
}
