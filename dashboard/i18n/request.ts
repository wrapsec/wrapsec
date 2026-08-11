// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { getRequestConfig } from "next-intl/server"
import { cookies } from "next/headers"
import localeConfig from "../messages/locale-config.json"

// The generated locale config is the ONLY place the dashboard learns which
// locales are supported (derived from locales/_meta.json). No hand-edited list.
const SUPPORTED: string[] = localeConfig.supported_locales
const DEFAULT_LOCALE: string = localeConfig.default_locale
const LOCALE_COOKIE = "wrapsec_locale"

/**
 * Locale resolution (User -> Tenant -> System -> English) belongs to WrapSec and
 * runs on the backend (services.localization.resolve_locale); the resolved value
 * is delivered to the browser as the wrapsec_locale cookie. Here we ONLY validate
 * that cookie against the generated allowlist and fall back to the default --
 * next-intl invents no precedence of its own.
 */
function pickLocale(cookieValue?: string): string {
  if (cookieValue) {
    const norm = cookieValue.trim().toLowerCase()
    const match = SUPPORTED.find((l) => l.toLowerCase() === norm)
    if (match) return match
  }
  return DEFAULT_LOCALE
}

type Messages = Record<string, unknown>

function deepMerge(base: Messages, override: Messages): Messages {
  const out: Messages = { ...base }
  for (const [k, v] of Object.entries(override)) {
    const b = out[k]
    out[k] = b && typeof b === "object" && v && typeof v === "object" && !Array.isArray(v)
      ? deepMerge(b as Messages, v as Messages)
      : v
  }
  return out
}

async function loadMessages(locale: string): Promise<Messages> {
  const en = (await import(`../messages/${DEFAULT_LOCALE}.json`)).default as Messages
  if (locale === DEFAULT_LOCALE) return en
  // English is the base; the active locale overrides it. A key the active locale
  // is missing resolves to English -- never to a backend string.
  const active = (await import(`../messages/${locale}.json`)).default as Messages
  return deepMerge(en, active)
}

export default getRequestConfig(async () => {
  const store = await cookies()
  const locale = pickLocale(store.get(LOCALE_COOKIE)?.value)
  return { locale, messages: await loadMessages(locale) }
})
