"use client"

import { createContext, useContext, useState, useEffect, useRef } from "react"

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

export function SidebarProvider({ children }: { children: React.ReactNode }) {
  const [collapsed,   setCollapsed]   = useState(false)
  const [sectionOpen, setSectionOpen] = useState<Record<string, boolean>>({
    configuration:  true,
    administration: true,
  })
  const hydrated = useRef(false)

  useEffect(() => {
    try {
      const c  = localStorage.getItem("sidebar_collapsed")
      const co = localStorage.getItem("sidebar_section_configuration")
      const ao = localStorage.getItem("sidebar_section_administration")

      if (c  === "true") setCollapsed(true)
      setSectionOpen({
        configuration:  co === null ? true : co === "true",
        administration: ao === null ? true : ao === "true",
      })
    } catch {}
    hydrated.current = true
  }, [])

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