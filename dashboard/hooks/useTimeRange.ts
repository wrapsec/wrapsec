// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
/**
 * useTimeRange — shared time range hook for Overview and Analytics pages.
 *
 * Encapsulates all time range state and from/to computation in one place.
 * No persistence by design — overview always opens at the default window,
 * showing current state rather than a stale previous selection.
 *
 * To add persistence in future (Option 5 — server-side user preference):
 *   1. Replace useState with a storage-backed version here only
 *   2. Page code and hook return shape stay identical — no other changes needed
 *
 * Usage:
 *   const { range, setRange, from, to } = useTimeRange()
 *   const { range, setRange, from, to } = useTimeRange({ defaultRange: "7d", options: ["24h","7d","30d","90d"] })
 */

import { useState, useMemo, useEffect } from "react"

export type TimeRange = "24h" | "7d" | "30d" | "90d"

interface UseTimeRangeOptions {
  defaultRange?: TimeRange
  options?:      TimeRange[]
  debounceMs?:   number   // default 300ms — prevents rapid switching from firing multiple requests
}

interface UseTimeRangeResult {
  range:    TimeRange          // immediate — use for selector UI
  setRange: (r: TimeRange) => void
  options:  TimeRange[]
  from:     string             // debounced — use for API calls
  to:       string             // debounced — use for API calls
}

const DEFAULT_OPTIONS: TimeRange[] = ["24h", "7d", "30d"]

function computeFromTo(range: TimeRange): { from: string; to: string } {
  const now  = new Date()
  const from = new Date(now)

  switch (range) {
    case "24h": from.setHours(now.getHours()  - 24);  break
    case "7d":  from.setDate(now.getDate()    - 7);   break
    case "30d": from.setDate(now.getDate()    - 30);  break
    case "90d": from.setDate(now.getDate()    - 90);  break
  }

  return {
    from: from.toISOString().slice(0, 19),
    to:   now.toISOString().slice(0, 19),
  }
}

export function useTimeRange(opts: UseTimeRangeOptions = {}): UseTimeRangeResult {
  const {
    defaultRange = "24h",
    options      = DEFAULT_OPTIONS,
    debounceMs   = 300,
  } = opts

  const [range,          setRange]          = useState<TimeRange>(defaultRange)
  const [debouncedRange, setDebouncedRange] = useState<TimeRange>(defaultRange)

  // Debounce — only update debouncedRange after user stops switching
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedRange(range), debounceMs)
    return () => clearTimeout(timer)
  }, [range, debounceMs])

  // from/to computed from debouncedRange — stable during rapid switching
  const { from, to } = useMemo(() => computeFromTo(debouncedRange), [debouncedRange])

  return { range, setRange, options, from, to }
}
