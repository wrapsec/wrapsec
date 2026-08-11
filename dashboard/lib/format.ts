// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * Locale-INDEPENDENT display helpers (percentages, latency, id/label rendering).
 *
 * FORMATTING POLICY (localization):
 * - LOCALE-SENSITIVE formatting (numbers, dates, times) lives in the useFormat
 *   hook, which follows the active locale. There is no hardcoded Intl locale in
 *   the codebase anymore.
 * - The helpers here are deliberately locale-independent: percentages and latency
 *   use a fixed representation, and truncateId/formatRun operate on machine ids.
 * - NEVER LOCALIZED (rendered verbatim -- machine/security contract): trace ids,
 *   error `code`, threat/severity codes (CRITICAL/HIGH/...), decision enums
 *   (BLOCK/ALLOW/SANITIZE), input_source, ValidationCode, and API identifiers
 *   (key_id, run_id, ids).
 */

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
