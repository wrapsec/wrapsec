// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useTranslations } from "next-intl"
import { ApiError } from "@/lib/apiError"

export type Severity = "ERROR" | "WARNING" | "INFO"

/**
 * The single localized error resolver. Every error surface (inline banners,
 * ErrorState, form field errors) goes through this so there is ONE error path.
 *
 * FALLBACK HIERARCHY (hard rule):
 *   known code -> ACTIVE-LOCALE catalog -> ENGLISH catalog -> raw backend message
 *   ONLY if the localization key itself is unknown.
 *
 * The active-locale -> English step is automatic: messages are loaded English-base
 * merged with the active locale (see i18n/request.ts), so a missing translation
 * resolves to English WITHOUT ever touching the backend string. We fall back to
 * the backend `message` only when `t.has(key)` is false (the key is unknown to
 * the catalog entirely).
 */
export function useErrorMessage() {
  const t = useTranslations()

  function resolve(err: unknown): { message: string; severity: Severity } {
    if (err instanceof ApiError && err.key && t.has(err.key)) {
      return {
        message:  t(err.key, err.params as Record<string, string | number> | undefined),
        severity: (err.severity as Severity) ?? "ERROR",
      }
    }
    // Unknown key (or non-API error) -> emergency raw message.
    const message  = err instanceof Error ? err.message : "Something went wrong."
    const severity = err instanceof ApiError ? ((err.severity as Severity) ?? "ERROR") : "ERROR"
    return { message, severity }
  }

  /**
   * Per-field 422 messages, keyed by machine field name. `labelFor` maps a
   * machine field to its localized label (forms.<entity>.<field>); the form
   * owns that mapping since it renders the inputs (rules sec 17).
   */
  function fieldErrors(
    err: unknown,
    labelFor?: (field: string) => string,
  ): Record<string, string> {
    const out: Record<string, string> = {}
    if (!(err instanceof ApiError)) return out
    for (const p of err.invalidParams) {
      const field  = labelFor ? labelFor(p.field) : p.field
      const values = { ...(p.params ?? {}), field } as Record<string, string | number>
      out[p.field] = t.has(p.key) ? t(p.key, values) : (err.message || p.field)
    }
    return out
  }

  return { resolve, fieldErrors }
}
