// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
/**
 * useTimeRange - shared time range hook for Overview and Analytics pages.
 *
 * Supports preset ranges (24h, 7d, 30d, 90d) and a "custom" mode where
 * the caller provides explicit YYYY-MM-DD from/to dates.
 *
 * Custom date validation rules (enforced in the hook):
 *   - Both dates must be non-empty, valid YYYY-MM-DD strings
 *   - `customFrom` must be before `customTo`
 *   - `customTo` cannot be in the future
 *   When invalid, `from`/`to` fall back to the previous valid preset output.
 */

import { useState, useMemo, useEffect } from "react"
import { presetRange, customRange, validateCustomRange } from "@/lib/datetime"

export type TimeRange = "24h" | "7d" | "30d" | "90d" | "custom"

const RANGE_DAYS: Record<Exclude<TimeRange, "custom">, number> = {
  "24h": 1, "7d": 7, "30d": 30, "90d": 90,
}

interface UseTimeRangeOptions {
  defaultRange?: Exclude<TimeRange, "custom">
  options?:      TimeRange[]
  debounceMs?:   number
}

interface UseTimeRangeResult {
  range:         TimeRange
  setRange:      (r: TimeRange) => void
  options:       TimeRange[]
  from:          string             // debounced - use for API calls
  to:            string             // debounced - use for API calls
  customFrom:    string             // raw input value for date picker
  customTo:      string             // raw input value for date picker
  setCustomFrom: (v: string) => void
  setCustomTo:   (v: string) => void
  customError:   string | null      // validation message - show in UI when non-null
}

const DEFAULT_OPTIONS: TimeRange[] = ["24h", "7d", "30d"]

export function useTimeRange(opts: UseTimeRangeOptions = {}): UseTimeRangeResult {
  const {
    defaultRange = "24h",
    options      = DEFAULT_OPTIONS,
    debounceMs   = 300,
  } = opts

  const [range,          setRange]          = useState<TimeRange>(defaultRange)
  const [debouncedRange, setDebouncedRange] = useState<TimeRange>(defaultRange)

  const [customFrom, setCustomFrom] = useState("")
  const [customTo,   setCustomTo]   = useState("")
  const [debouncedCustomFrom, setDebouncedCustomFrom] = useState("")
  const [debouncedCustomTo,   setDebouncedCustomTo]   = useState("")

  // Debounce preset range switching
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedRange(range), debounceMs)
    return () => clearTimeout(timer)
  }, [range, debounceMs])

  // Debounce custom date inputs separately
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedCustomFrom(customFrom)
      setDebouncedCustomTo(customTo)
    }, debounceMs)
    return () => clearTimeout(timer)
  }, [customFrom, customTo, debounceMs])

  const customError = range === "custom" ? validateCustomRange(customFrom, customTo) : null

  const { from, to } = useMemo(() => {
    if (debouncedRange === "custom") {
      const err = validateCustomRange(debouncedCustomFrom, debouncedCustomTo)
      if (!err) return customRange(debouncedCustomFrom, debouncedCustomTo)
      // Fall back to 7d while custom is being filled in
      return presetRange(7)
    }
    return presetRange(RANGE_DAYS[debouncedRange as Exclude<TimeRange, "custom">])
  }, [debouncedRange, debouncedCustomFrom, debouncedCustomTo])

  return {
    range, setRange, options, from, to,
    customFrom, setCustomFrom,
    customTo,   setCustomTo,
    customError,
  }
}
