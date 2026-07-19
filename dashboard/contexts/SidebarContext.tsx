// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { createContext, useContext, useState } from "react"

interface SidebarContextValue {
  collapsed:       boolean
  toggleCollapsed: (v: boolean) => void
  sectionOpen:     Record<string, boolean>
  toggleSection:   (key: string) => void
}

const SidebarContext = createContext<SidebarContextValue>({
  collapsed:       false,
  toggleCollapsed: () => {},
  sectionOpen:     { configuration: true, administration: true },
  toggleSection:   () => {},
})

// SSR-safe localStorage read. The initializer runs during the very first
// useState() call - on the server `window` is undefined so we return the
// default; on the client hydration React uses the actual persisted value.
// This replaces the previous setState-inside-useEffect pattern flagged by
// react-hooks/set-state-in-effect (pentest H13).
function readBool(key: string, fallback: boolean): boolean {
  if (typeof window === "undefined") return fallback
  try {
    const raw = window.localStorage.getItem(key)
    if (raw === null) return fallback
    return raw === "true"
  } catch {
    return fallback
  }
}

export function SidebarProvider({ children }: { children: React.ReactNode }) {
  const [collapsed,   setCollapsed]   = useState<boolean>(() =>
    readBool("sidebar_collapsed", false),
  )
  const [sectionOpen, setSectionOpen] = useState<Record<string, boolean>>(() => ({
    configuration:  readBool("sidebar_section_configuration",  true),
    administration: readBool("sidebar_section_administration", true),
  }))

  const toggleCollapsed = (v: boolean) => {
    setCollapsed(v)
    try { localStorage.setItem("sidebar_collapsed", String(v)) } catch {}
  }

  const toggleSection = (key: string) => {
    setSectionOpen(prev => {
      const next = { ...prev, [key]: !prev[key] }
      try { localStorage.setItem(`sidebar_section_${key}`, String(next[key])) } catch {}
      return next
    })
  }

  return (
    <SidebarContext.Provider value={{ collapsed, toggleCollapsed, sectionOpen, toggleSection }}>
      {children}
    </SidebarContext.Provider>
  )
}

export const useSidebar = () => useContext(SidebarContext)
