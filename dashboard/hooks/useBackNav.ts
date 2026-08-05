// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useCallback } from "react"
import { useRouter } from "next/navigation"

/**
 * The one Back convention for every resource route.
 *
 * Returns a `goBack()` that navigates to the exact prior in-app state when there
 * is navigation history (preserving the list's filters / page / sort), and falls
 * back to the parent list route for a cold deep-link (a URL pasted into a fresh
 * tab, where Back would otherwise leave the app or dead-end).
 *
 *   const goBack = useBackNav("/requests")
 */
export function useBackNav(fallbackHref: string) {
  const router = useRouter()
  return useCallback(() => {
    // history.length > 1 means we arrived here from another in-app page; a fresh
    // tab opened straight on this route has length 1 -> use the fallback list.
    if (typeof window !== "undefined" && window.history.length > 1) {
      router.back()
    } else {
      router.push(fallbackHref)
    }
  }, [router, fallbackHref])
}
