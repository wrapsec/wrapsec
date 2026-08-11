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

export default getRequestConfig(async () => {
  const store = await cookies()
  const locale = pickLocale(store.get(LOCALE_COOKIE)?.value)
  const messages = (await import(`../messages/${locale}.json`)).default
  return { locale, messages }
})
