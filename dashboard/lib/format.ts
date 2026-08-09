// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * Single source for number formatting. Centralizing these means a change to how
 * the dashboard renders counts, percentages, or latencies (locale, precision)
 * happens in one place rather than at every call site.
 */

/** Integer/count with locale grouping (e.g. "12,340"). */
export function formatNumber(n: number): string {
  return n.toLocaleString()
}

/**
 * Compact count for fixed-width KPI cards (e.g. "1.2K", "3.4M", "1.2B"). Keeps
 * large values from overflowing a narrow card; pair with the full formatNumber
 * in a hover title. Values under 1,000 render as-is.
 */
export function formatCompact(n: number): string {
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n)
}

/** Risk score (0..1) as a whole-number percentage (e.g. "92%"). */
export function formatScore(score: number): string {
  return (score * 100).toFixed(0) + "%"
}

/** Rate (0..1) as a one-decimal percentage (e.g. "12.5%"). */
export function formatRate(rate: number): string {
  return (rate * 100).toFixed(1) + "%"
}

/** Latency in ms, switching to seconds above 1000ms (e.g. "45ms", "1.2s"). */
export function formatLatency(ms: number): string {
  if (ms < 1000) return ms.toFixed(0) + "ms"
  return (ms / 1000).toFixed(1) + "s"
}

/**
 * Compact form of a long opaque id for table rows: keeps a readable head and the
 * last `tail` chars so rows stay scannable while the id stays recognizable. The
 * full id lives in the detail drawer (with copy). Short ids are returned as-is.
 */
export function truncateId(id: string, tail = 7): string {
  if (id.length <= tail + 5) return id
  const us = id.indexOf("_")
  const head = us > 0 && us <= 6 ? id.slice(0, us + 1) : id.slice(0, 4)
  return head + "..." + id.slice(-tail)
}

/** Short agent-run label for a row/hero, e.g. "run 63c9b6 . turn 1". */
export function formatRun(runId: string, turnIndex?: number | null): string {
  const base = `run ${runId.slice(-6)}`
  return turnIndex != null ? `${base} . turn ${turnIndex}` : base
}
