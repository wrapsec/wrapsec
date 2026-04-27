"use client"

import { useRef } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { useSidebar } from "@/contexts/SidebarContext"

// ── Icons ──────────────────────────────────────────────────────────────────

const Icons = {
  overview: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
    </svg>
  ),
  requests: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
    </svg>
  ),
  analytics: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
  ),
  scanner: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
    </svg>
  ),
  settings: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  ),
  keys: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
    </svg>
  ),
  departments: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
    </svg>
  ),
  applications: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" />
    </svg>
  ),
  system: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
    </svg>
  ),
  chevronDown: (
    <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
    </svg>
  ),
  chevronLeft: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
    </svg>
  ),
  chevronRight: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
    </svg>
  ),
  users: (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
    </svg>
  ),
  shield: (
    <svg className="h-4 w-4 text-white" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
}

// ── Nav data ───────────────────────────────────────────────────────────────

const NAV_ITEMS = [
  { label: "Overview",  href: "/",          icon: Icons.overview,  exact: true  },
  { label: "Requests",  href: "/requests",  icon: Icons.requests,  exact: false },
  { label: "Analytics", href: "/analytics", icon: Icons.analytics, exact: false },
  { label: "Scanner",   href: "/scanner",   icon: Icons.scanner,   exact: false },
]

const CONFIG_ITEMS = [
  { label: "Settings", href: "/settings",      icon: Icons.settings, exact: true  },
  { label: "API Keys", href: "/settings/keys", icon: Icons.keys,     exact: true  },
]

const ADMIN_ITEMS = [
  { label: "Users",        href: "/users",        icon: Icons.users,        exact: false },
  { label: "Departments",  href: "/departments",  icon: Icons.departments,  exact: false },
  { label: "Applications", href: "/applications", icon: Icons.applications, exact: false },
  { label: "System",       href: "/system",       icon: Icons.system,       exact: false },
]

// ── NavLink ────────────────────────────────────────────────────────────────

function NavLink({
  item,
  collapsed,
  active,
}: {
  item:      { label: string; href: string; icon: React.ReactNode }
  collapsed: boolean
  active:    boolean
}) {
  return (
    <Link
      href={item.href}
      title={collapsed ? item.label : undefined}
      className={cn(
          "flex items-center gap-2.5 py-2 rounded-md text-sm transition-colors duration-150 w-full",
          collapsed ? "justify-center px-1" : "px-2",
        active
          ? "bg-blue-50 text-blue-800 font-medium"
          : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
      )}
    >
      <span className={cn("flex-shrink-0", active ? "text-blue-800" : "text-slate-400")}>
        {item.icon}
      </span>
      {!collapsed && <span className="truncate">{item.label}</span>}
    </Link>
  )
}

// ── NavSection ─────────────────────────────────────────────────────────────

function NavSection({
  label,
  sectionKey,
  items,
  collapsed,
  pathname,
}: {
  label:      string
  sectionKey: string
  items:      { label: string; href: string; icon: React.ReactNode; exact: boolean }[]
  collapsed:  boolean
  pathname:   string
}) {
  const { sectionOpen, toggleSection } = useSidebar()
  const open = sectionOpen[sectionKey] ?? true

  return (
    <div className="pt-3">
      {!collapsed && (
        <button
          onClick={() => toggleSection(sectionKey)}
          className="w-full flex items-center justify-between px-2 py-1 mb-0.5 group"
        >
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider group-hover:text-slate-600 transition-colors">
            {label}
          </span>
          <span
            className="text-slate-300 group-hover:text-slate-500 inline-flex transition-transform duration-200"
            style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
          >
            {Icons.chevronDown}
          </span>
        </button>
      )}

      {collapsed && <div className="mx-2 mb-1 border-t border-slate-100" />}

      <div
        style={{
          maxHeight:  collapsed ? "none" : (open ? "500px" : "0px"),
          overflow:   "hidden",
          transition: "max-height 220ms ease-in-out",
        }}
      >
        <div className="space-y-0.5">
          {items.map((item) => {
            const active = item.exact
              ? pathname === item.href
              : pathname.startsWith(item.href)
            return (
              <NavLink
                key={item.href}
                item={item}
                collapsed={collapsed}
                active={active}
              />
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ── Sidebar ────────────────────────────────────────────────────────────────

export function Sidebar() {
  const pathname                    = usePathname()
  const { collapsed, toggleCollapsed } = useSidebar()
  const sidebarWidth                = collapsed ? 50 : 224

  return (
    <>
      <aside
        className="fixed top-0 left-0 h-screen bg-white border-r border-slate-200 flex flex-col z-30 overflow-hidden transition-[width] duration-300 ease-in-out"
        style={{ width: sidebarWidth }}
      >
        {/* Header */}
        <div className="flex items-center h-14 border-b border-slate-200 flex-shrink-0 px-3 gap-2.5">
          <div className="h-7 w-7 rounded-md bg-blue-800 flex items-center justify-center flex-shrink-0">
            {Icons.shield}
          </div>

          {/* Brand — always mounted, fades via opacity */}
          <div
            className="flex-1 min-w-0 overflow-hidden transition-[opacity,max-width] duration-300 ease-in-out"
            style={{
              opacity:  collapsed ? 0 : 1,
              maxWidth: collapsed ? "0px" : "200px",
            }}
          >
            <p className="text-sm font-semibold text-slate-900 leading-none whitespace-nowrap">WrapSec</p>
            <p className="text-xs text-slate-400 leading-none mt-0.5 whitespace-nowrap">AI Security Gateway</p>
          </div>

          {!collapsed && (
            <button
              onClick={() => toggleCollapsed(true)}
              className="flex-shrink-0 p-1 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors ml-auto"
              title="Collapse sidebar"
            >
              {Icons.chevronLeft}
            </button>
          )}
        </div>

        {/* Expand button */}
        {collapsed && (
          <div className="flex justify-center mt-2">
            <button
              onClick={() => toggleCollapsed(false)}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors"
              title="Expand sidebar"
            >
              {Icons.chevronRight}
            </button>
          </div>
        )}

        {/* Nav */}
        <nav
          className="flex-1 py-3 space-y-0.5 overflow-y-auto overflow-x-hidden"
          style={{ padding: collapsed ? "12px 2px" : "12px 4px" }}
        >
          {NAV_ITEMS.map((item) => {
            const active = item.exact
              ? pathname === item.href
              : pathname.startsWith(item.href)
            return (
              <NavLink key={item.href} item={item} collapsed={collapsed} active={active} />
            )
          })}

          <NavSection
            label="Configuration"
            sectionKey="configuration"
            items={CONFIG_ITEMS}
            collapsed={collapsed}
            pathname={pathname}
          />
          <NavSection
            label="Administration"
            sectionKey="administration"
            items={ADMIN_ITEMS}
            collapsed={collapsed}
            pathname={pathname}
          />
        </nav>

        {!collapsed && (
          <div className="px-4 py-3 border-t border-slate-200 flex-shrink-0">
            <p className="text-xs text-slate-400">WrapSec v1.0.0</p>
          </div>
        )}
      </aside>

      {/* Spacer */}
      <div
        className="flex-shrink-0 transition-[width] duration-300 ease-in-out"
        style={{ width: sidebarWidth }}
      />
    </>
  )
}
