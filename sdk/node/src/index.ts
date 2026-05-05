// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * WrapSec Node.js SDK — public exports.
 *
 * Usage:
 *   import WrapSec from 'wrapsec-node'
 *   import { WrapSecError, WrapSecBlockError } from 'wrapsec-node'
 *
 *   import { wrapSecMiddleware } from 'wrapsec-node/middleware/express'
 *   import wrapSecPlugin from 'wrapsec-node/middleware/fastify'
 */

export { WrapSec } from "./client"

export {
  WrapSecError,
  WrapSecAuthError,
  WrapSecRateLimitError,
  WrapSecSystemError,
  WrapSecBlockError,
} from "./exceptions"

export type {
  WrapSecConfig,
  ScanResult,
  ScanOptions,
  AuditLog,
  AuditStats,
  AuditListOptions,
  ExpressMiddlewareOptions,
} from "./types"

// Re-export Fastify plugin options so consumers can type-annotate their config:
// import type { FastifyPluginOptions } from 'wrapsec-node'
export type { FastifyPluginOptions } from "./middleware/fastify"

// Default export for convenience: import WrapSec from 'wrapsec-node'
export { WrapSec as default } from "./client"
