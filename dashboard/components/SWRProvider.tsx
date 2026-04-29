"use client"

import { SWRConfig } from "swr"

/**
 * Global SWR cache provider.
 *
 * Uses globalThis to store the cache Map — survives Next.js hot module
 * replacement in development (Turbopack destroys module-level vars on HMR
 * but globalThis persists for the browser session).
 *
 * In production there is no HMR so this makes no difference — module-level
 * const would work fine, but globalThis works in both environments.
 *
 * Security: in-memory only, never written to any storage, cleared on reload.
 */

declare global {
  // eslint-disable-next-line no-var
  var __swrCache: Map<string, unknown> | undefined
}

function getCache(): Map<string, unknown> {
  if (!globalThis.__swrCache) {
    globalThis.__swrCache = new Map()
  }
  return globalThis.__swrCache
}

export function SWRProvider({ children }: { children: React.ReactNode }) {
  return (
    <SWRConfig value={{ provider: getCache }}>
      {children}
    </SWRConfig>
  )
}
