// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * Express middleware for WrapSec.
 *
 * Enforces a 64KB payload limit before calling the API.
 * Scans the request body and blocks or passes through.
 *
 * Spec reference: Section 18.3 (Express Middleware Limits)
 *
 * Usage:
 *   import { wrapSecMiddleware } from 'wrapsec-node/middleware'
 *   app.use('/api/ai', wrapSecMiddleware({ apiKey: '...', onBlock: (req, res) => ... }))
 */

import type { Request, Response, NextFunction } from "express"
import { WrapSec } from "../client"
import type { ExpressMiddlewareOptions, ScanResult } from "../types"

/** Max payload in bytes — enforced before API call. Spec §18.3 */
const MAX_PAYLOAD_BYTES = 64 * 1024   // 64KB

/**
 * Extract text to scan from the request body.
 * Handles: string body, { input: string } body, or custom inputKey.
 */
function extractInput(req: Request, inputKey?: string): string | null {
  const body = req.body

  // #2 — explicit null/undefined check before any property access
  if (body === null || body === undefined) return null

  if (typeof body === "string") return body

  // #2 — confirm body is a plain object (not array, Date, etc.) before key access
  if (typeof body === "object" && !Array.isArray(body)) {
    const key   = inputKey ?? "input"
    const value = (body as Record<string, unknown>)[key]
    if (typeof value === "string") return value
  }

  // Fallback: OpenAI-style messages array
  if (typeof body === "object" && body !== null) {
    const messages = (body as any).messages
    if (Array.isArray(messages)) {
      return messages
        .map((m: unknown) => {
          // #2 — confirm m is object and content is string before accessing
          if (m !== null && typeof m === "object" && typeof (m as any).content === "string") {
            return (m as any).content as string
          }
          return ""
        })
        .filter(Boolean)
        .join("\n") || null
    }
  }

  return null
}

/**
 * Express middleware factory.
 *
 * Returns a middleware function that:
 *   1. Extracts input text from request body
 *   2. Enforces 64KB payload limit (returns 413 if exceeded)
 *   3. Scans with WrapSec
 *   4. On BLOCK: calls onBlock or returns 403 JSON
 *   5. On ALLOW/SANITIZE: calls next() (with sanitized input if applicable)
 *   6. On error: calls next(err) for Express error handler
 *
 * Spec: Section 18.1, Section 18.3
 */
export function wrapSecMiddleware(options: ExpressMiddlewareOptions = {}) {
  const client = new WrapSec({
    apiKey:  options.apiKey,
    baseUrl: options.baseUrl,
    timeout: options.timeout,
  })

  const mode     = options.mode     ?? "fast"
  const inputKey = options.inputKey ?? "input"

  const defaultOnBlock = (_req: Request, res: Response, _result: ScanResult): void => {
    res.status(403).json({
      error: {
        code:    "input_blocked",
        message: "Request blocked by security policy.",
      },
    })
  }

  const onBlock = options.onBlock ?? defaultOnBlock

  return async function wrapsecMiddleware(
    req:  Request,
    res:  Response,
    next: NextFunction,
  ): Promise<void> {
    try {
      // Extract text to scan
      const text = extractInput(req, inputKey)
      if (!text) {
        // No scannable input — pass through
        return next()
      }

      // Enforce 64KB limit BEFORE API call — Spec §18.3
      const byteLength = Buffer.byteLength(text, "utf8")
      if (byteLength > MAX_PAYLOAD_BYTES) {
        res.status(413).json({
          error: {
            code:    "PAYLOAD_TOO_LARGE",
            message: `Input exceeds 64KB limit (${byteLength} bytes).`,
          },
        })
        return
      }

      // Scan
      const result = await client.scan(text, { mode })

      if (result.isBlocked) {
        onBlock(req, res, result)
        return
      }

      // Attach WrapSec result to request for downstream handlers
      ;(req as any).wrapsec = result

      // If sanitized, update body input field with sanitized version
      if (result.isSanitized && result.sanitizedInput) {
        if (typeof req.body === "object" && req.body !== null) {
          req.body[inputKey] = result.sanitizedInput
        }
      }

      next()
    } catch (err) {
      // Pass errors to Express error handler — do not block on WrapSec failure
      next(err)
    }
  }
}
