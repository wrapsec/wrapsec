// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useLocale } from "next-intl"
import { ensureUtc } from "@/lib/datetime"

/**
 * The single locale-aware formatting hook. Replaces the previously hardcoded
 * Intl locales (en-US for numbers, en-GB for dates) so number/date rendering
 * follows the active locale. Uses the next-intl active locale (same source as
 * t()), so SSR and client render identically (no hydration mismatch).
 *
 * FORMATTING POLICY: this covers the LOCALE-SENSITIVE formatters only. Locale-
 * independent helpers (percentages, latency, relative time, id truncation, and
 * the UTC range helpers) stay pure functions in lib/format + lib/datetime and
 * are not routed through here. Machine/security values (trace ids, codes, enums)
 * are never formatted.
 *
 * Output is preserved for `en`: numbers use the active locale, dates map en ->
 * en-GB (the app's existing day/month, 24h convention). A new locale uses its
 * own conventions.
 */
const DATE_LOCALE: Record<string, string> = {
  en: "en-GB",
}

export function useFormat() {
  const locale     = useLocale()
  const dateLocale = DATE_LOCALE[locale] ?? locale

  return {
    /** Integer/count with locale grouping (e.g. "12,340"). */
    number(n: number): string {
      return n.toLocaleString(locale)
    },
    /** Compact count for narrow KPI cards (e.g. "1.2K", "3.4M"). */
    compact(n: number): string {
      return new Intl.NumberFormat(locale, { notation: "compact", maximumFractionDigits: 1 }).format(n)
    },
    /** Instant in the viewer's local timezone (date + time). */
    timestamp(ts: string): string {
      return ensureUtc(ts).toLocaleString(dateLocale, {
        day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
      })
    },
    /** Instant as a local date only (no time). */
    date(ts: string): string {
      return ensureUtc(ts).toLocaleDateString(dateLocale, {
        day: "2-digit", month: "short", year: "numeric",
      })
    },
  }
}
