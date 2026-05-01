// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * Fastify plugin for WrapSec.
 *
 * Usage:
 *   import wrapSecPlugin from 'wrapsec-node/middleware/fastify'
 *   await fastify.register(wrapSecPlugin, { apiKey: '...' })
 *
 *   // Or on a specific route:
 *   fastify.addHook('preHandler', wrapSecPlugin.hook({ apiKey: '...' }))
 */

import { WrapSec } from "../client"
import type { ScanResult } from "../types"

const MAX_PAYLOAD_BYTES = 64 * 1024   // 64KB — Spec §18.3

export interface FastifyPluginOptions {
  apiKey?:  string
  baseUrl?: string
  timeout?: number
  mode?:    "fast" | "full"
  inputKey?: string
  onBlock?: (request: any, reply: any, result: ScanResult) => void
}

/**
 * Fastify plugin — registers a preHandler hook on all routes.
 *
 * Spec: Section 18.1 (Fastify plugin parity with Express middleware)
 */
async function wrapSecPlugin(fastify: any, options: FastifyPluginOptions) {
  const client = new WrapSec({
    apiKey:  options.apiKey,
    baseUrl: options.baseUrl,
    timeout: options.timeout,
  })

  const mode     = options.mode     ?? "fast"
  const inputKey = options.inputKey ?? "input"

  const defaultOnBlock = (_request: any, reply: any, _result: ScanResult): void => {
    reply.status(403).send({
      error: {
        code:    "input_blocked",
        message: "Request blocked by security policy.",
      },
    })
  }

  const onBlock = options.onBlock ?? defaultOnBlock

  fastify.addHook("preHandler", async (request: any, reply: any) => {
    const body = request.body
    if (!body) return

    // Extract text
    let text: string | null = null
    if (typeof body === "string") {
      text = body
    } else if (typeof body === "object") {
      const value = body[inputKey]
      if (typeof value === "string") text = value
    }

    if (!text) return

    // 64KB limit — Spec §18.3
    const byteLength = Buffer.byteLength(text, "utf8")
    if (byteLength > MAX_PAYLOAD_BYTES) {
      reply.status(413).send({
        error: {
          code:    "PAYLOAD_TOO_LARGE",
          message: `Input exceeds 64KB limit (${byteLength} bytes).`,
        },
      })
      return
    }

    try {
      const result = await client.scan(text, { mode })

      if (result.isBlocked) {
        onBlock(request, reply, result)
        return
      }

      request.wrapsec = result

      if (result.isSanitized && result.sanitizedInput) {
        if (typeof request.body === "object") {
          request.body[inputKey] = result.sanitizedInput
        }
      }
    } catch {
      // Do not block requests on WrapSec errors — log and continue
      fastify.log.error("WrapSec scan failed — passing request through")
    }
  })
}

export default wrapSecPlugin
export { wrapSecPlugin }
