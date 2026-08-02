// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * Single source of date/time handling for the dashboard.
 *
 * The API stores and returns UTC (ISO-8601 with a trailing `Z`). Conversion to
 * the viewer's timezone is a presentation concern and happens here: display
 * helpers render in the browser's local zone, and range helpers build the
 * from/to filter values the API expects.
 *
 * `ensureUtc` keeps parsing robust against any value that arrives without a
 * timezone marker by treating it as UTC -- the backend always sends `Z` now,
 * but a naive string must never be misread as browser-local (the v1.2.x class
 * of date-boundary bug).
 */

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/

/** Parse an ISO timestamp, treating a timezone-less value as UTC. */
export function ensureUtc(ts: string): Date {
  const hasZone = ts.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(ts)
  return new Date(hasZone ? ts : ts + "Z")
}

/** Display an instant in the viewer's local timezone (date + time). */
export function formatTimestamp(ts: string): string {
  return ensureUtc(ts).toLocaleString("en-GB", {
    day:    "2-digit",
    month:  "short",
    hour:   "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}

/** Display an instant as a local date only (no time). */
export function formatDate(ts: string): string {
  return ensureUtc(ts).toLocaleDateString("en-GB", {
    day:   "2-digit",
    month: "short",
    year:  "numeric",
  })
}

/** Compact relative-time label ("5m ago"). */
export function timeAgo(ts: string): string {
  const diff = Date.now() - ensureUtc(ts).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

// --- range helpers for the time-range filter --------------------------

export function isValidDate(s: string): boolean {
  return DATE_RE.test(s) && !isNaN(new Date(s).getTime())
}

/** from/to (UTC, second precision) for a preset window ending now. */
export function presetRange(days: number): { from: string; to: string } {
  const now  = new Date()
  const from = new Date(now)
  from.setDate(now.getDate() - days)
  return {
    from: from.toISOString().slice(0, 19),
    to:   now.toISOString().slice(0, 19),
  }
}

/** from/to for an explicit YYYY-MM-DD custom range (full days). */
export function customRange(fromDate: string, toDate: string): { from: string; to: string } {
  return {
    from: fromDate + "T00:00:00",
    to:   toDate   + "T23:59:59",
  }
}

/** Validation message for a custom YYYY-MM-DD range, or null when valid. */
export function validateCustomRange(from: string, to: string): string | null {
  if (!from || !to)       return "Both dates are required"
  if (!isValidDate(from)) return "Invalid start date"
  if (!isValidDate(to))   return "Invalid end date"
  if (from >= to)         return "Start date must be before end date"
  const today = new Date().toISOString().slice(0, 10)
  if (to > today)         return "End date cannot be in the future"
  return null
}
