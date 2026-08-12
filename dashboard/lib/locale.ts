// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

// Shared client-side locale helpers. The generated locale-config.json (derived
// from locales/_meta.json) is the ONLY place the dashboard learns which locales
// are supported and their metadata -- no hand-maintained list here.
//
// ARCHITECTURE RULE: the wrapsec_locale cookie is written ONLY from a locale the
// backend has RESOLVED and returned (login / refresh / PATCH /me), never from a
// requested value. writeLocaleCookie() therefore takes an already-resolved value
// and callers must pass the backend's result, not user input.

import localeConfig from "@/messages/locale-config.json"

export const LOCALE_COOKIE = "wrapsec_locale"

// Match the BFF login cookie lifetime (session ~= refresh token, 30d default).
const MAX_AGE_S = 60 * 60 * 24 * 30

export const SUPPORTED_LOCALES = localeConfig.supported_locales as string[]
export const DEFAULT_LOCALE    = localeConfig.default_locale as string
export const LOCALE_LABELS     = localeConfig.labels as Record<string, string>
export const LOCALE_DIRECTIONS = localeConfig.directions as Record<string, "ltr" | "rtl">

/** Current wrapsec_locale cookie value, or null when absent / server-side. */
export function readLocaleCookie(): string | null {
  if (typeof document === "undefined") return null
  const m = document.cookie.match(new RegExp(`(?:^|;\\s*)${LOCALE_COOKIE}=([^;]*)`))
  return m ? decodeURIComponent(m[1]) : null
}

/** Write the wrapsec_locale cookie. `resolved` MUST be a backend-resolved value. */
export function writeLocaleCookie(resolved: string): void {
  if (typeof document === "undefined") return
  const secure = window.location.protocol === "https:" ? "; Secure" : ""
  document.cookie =
    `${LOCALE_COOKIE}=${encodeURIComponent(resolved)}; Path=/; Max-Age=${MAX_AGE_S}; SameSite=Strict${secure}`
}
