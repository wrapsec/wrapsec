// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useCallback, useMemo, useRef, useState } from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"

/**
 * Spec for one list page's query params. Each param declares a default; a
 * `debounce` (ms) marks a text field whose URL commit should be debounced.
 */
export type ParamSpec = Record<string, { default: string; debounce?: number }>

/**
 * Generic, module-agnostic list-page state kept in the URL.
 *
 * The URL is the single source of truth for filters, sort, and pagination, so
 * Back / refresh / deep-links always restore the exact view. Any list page
 * (Requests today; Policies / API Keys / MCP Servers / Knowledge Bases /
 * Evaluations tomorrow) adopts it by declaring its param spec -- no per-page
 * URL plumbing.
 *
 *   const { values, setParam, setParams, text } = useListParams({
 *     decision: { default: "" },
 *     offset:   { default: "0" },
 *     q:        { default: "", debounce: 400 },
 *   })
 *
 * Writes use router.replace (scroll preserved) so filtering does not spam the
 * history stack. Only non-sensitive navigation state belongs here -- never
 * tokens, secrets, or PII.
 */
export function useListParams<T extends ParamSpec>(spec: T) {
  const router       = useRouter()
  const pathname     = usePathname()
  const searchParams = useSearchParams()
  const search       = searchParams.toString()

  const values = useMemo(() => {
    const out = {} as Record<keyof T, string>
    for (const key of Object.keys(spec) as (keyof T)[]) {
      out[key] = searchParams.get(key as string) ?? spec[key].default
    }
    return out
  }, [searchParams, spec])

  // Apply one or more param updates atomically. Pass every field that changes
  // together in a SINGLE call (e.g. "Clear all", or clearing a date range that
  // resets both `from` and `to`) -- issuing several setParams calls in the same
  // tick would each read the same stale `search` and clobber one another.
  const setParams = useCallback((updates: Partial<Record<keyof T, string>>) => {
    const params = new URLSearchParams(search)
    for (const [key, val] of Object.entries(updates)) {
      const def = spec[key as keyof T]?.default
      // Drop a param at its default so canonical/default URLs stay clean.
      if (val === undefined || val === null || val === "" || val === def) {
        params.delete(key)
      } else {
        params.set(key, String(val))
      }
    }
    const qs = params.toString()
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false })
  }, [router, pathname, search, spec])

  const setParam = useCallback(
    <K extends keyof T>(key: K, val: string) =>
      setParams({ [key]: val } as Partial<Record<keyof T, string>>),
    [setParams],
  )

  // --- debounced text fields ---
  // Local immediate value for responsive typing; the URL commit is debounced.
  const [local, setLocal] = useState<Record<string, string>>({})
  const timers = useRef<Record<string, ReturnType<typeof setTimeout>>>({})

  const textValue = useCallback(
    (key: keyof T): string => local[key as string] ?? values[key],
    [local, values],
  )

  const onTextChange = useCallback(
    (key: keyof T, val: string, extra?: Partial<Record<keyof T, string>>) => {
      setLocal(prev => ({ ...prev, [key as string]: val }))
      const ms = spec[key].debounce ?? 0
      clearTimeout(timers.current[key as string])
      timers.current[key as string] = setTimeout(
        () => setParams({ [key]: val, ...(extra ?? {}) } as Partial<Record<keyof T, string>>),
        ms,
      )
    },
    [spec, setParams],
  )

  return { values, setParam, setParams, textValue, onTextChange }
}
