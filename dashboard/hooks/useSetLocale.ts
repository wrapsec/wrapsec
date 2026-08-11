// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useRouter } from "next/navigation"

const LOCALE_COOKIE = "wrapsec_locale"
// Match the BFF login cookie lifetime (session ~= refresh token, 30d default).
const MAX_AGE_S = 60 * 60 * 24 * 30

function writeLocaleCookie(locale: string): void {
  const secure = typeof window !== "undefined" && window.location.protocol === "https:" ? "; Secure" : ""
  document.cookie =
    `${LOCALE_COOKIE}=${encodeURIComponent(locale)}; Path=/; Max-Age=${MAX_AGE_S}; SameSite=Strict${secure}`
}

/**
 * Change the current user's locale preference and reflect it immediately.
 *
 * Flow: PATCH /api/proxy/v1/auth/me { locale } -> receive the backend's
 * VALIDATED, RESOLVED locale -> update the wrapsec_locale cookie from that ->
 * router.refresh() so server components re-render and next-intl re-reads the
 * cookie.
 *
 * ARCHITECTURE RULE: the cookie is set from the backend's returned
 * `resolved_locale` (User -> Tenant -> System -> English), NEVER from the
 * requested value. Resolution + validation belong to WrapSec; the client only
 * mirrors the result. An unsupported request is rejected 422 by the backend and
 * this throws without touching the cookie.
 *
 * (No locale-switcher UI ships yet; this is the wired mechanism a future
 * switcher calls.)
 */
export function useSetLocale() {
  const router = useRouter()

  return async function setLocale(locale: string): Promise<string> {
    const res = await fetch("/api/proxy/v1/auth/me", {
      method:  "PATCH",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ locale }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err?.error?.message || `Failed to set locale (${res.status})`)
    }

    const data = await res.json()
    const resolved: string = data.resolved_locale
    writeLocaleCookie(resolved)
    router.refresh()
    return resolved
  }
}
