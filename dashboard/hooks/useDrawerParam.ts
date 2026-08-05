// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useCallback } from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"

/**
 * URL-addressable row peek (the dashboard "drawer" convention).
 *
 * A table row opens a detail drawer by writing `?<name>=<id>` to the URL, so the
 * peek is deep-linkable, refresh-safe, and closing it returns to the exact same
 * list. `open` pushes a history entry (browser Back also closes the drawer);
 * `close` removes the param in place.
 *
 *   const { openId, open, close } = useDrawerParam("peek")
 *   // row onClick -> open(traceId);  drawer onClose -> close()
 *
 * The id is opaque navigation state (e.g. a trace_id) -- never a secret or PII.
 */
export function useDrawerParam(name: string) {
  const router       = useRouter()
  const pathname     = usePathname()
  const searchParams = useSearchParams()
  const openId       = searchParams.get(name)

  const open = useCallback((id: string) => {
    const params = new URLSearchParams(searchParams.toString())
    params.set(name, id)
    router.push(`${pathname}?${params.toString()}`, { scroll: false })
  }, [router, pathname, searchParams, name])

  const close = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString())
    params.delete(name)
    const qs = params.toString()
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false })
  }, [router, pathname, searchParams, name])

  return { openId, open, close }
}
