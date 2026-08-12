// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { useSidebar } from "@/contexts/SidebarContext"
import { AboutModal } from "./AboutModal"

// ── WrapSec logo mark (4 strokes from SVG) ────────────────────────────────

function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 249 221" fill="none">
      <g transform="matrix(1,0,0,1,-375.623461,-389.613053)">
        <g transform="matrix(1,0,0,1,-0,22.207172)">
          <g transform="matrix(1.835477,-1.386843,2.13606,2.827061,252.359105,497.387654)">
            <path d="M160,35C160,37.76 156.549,40 152.299,40L107.701,40C103.451,40 100,37.76 100,35C100,32.24 103.451,30 107.701,30L152.299,30C156.549,30 160,32.24 160,35Z" fill="#670FEF"/>
          </g>
          <g transform="matrix(-0.81495,1.114041,-2.859803,-2.09202,653.361273,461.347338)">
            <path d="M160,35C160,37.76 154.249,40 147.165,40L112.835,40C105.751,40 100,37.76 100,35C100,32.24 105.751,30 112.835,30L147.165,30C154.249,30 160,32.24 160,35Z" fill="#CD00FF"/>
          </g>
          <g transform="matrix(0.975083,1.240032,-2.785324,2.190204,674.397302,330.426277)">
            <path d="M90,65C90,67.76 84.968,70 78.769,70L31.231,70C25.032,70 20,67.76 20,65C20,62.24 25.032,60 31.231,60L78.769,60C84.968,60 90,62.24 90,65Z" fill="#00E1FF"/>
          </g>
          <g transform="matrix(2.248397,1.601761,-2.055903,2.885877,265.218885,33.107289)">
            <path d="M150,65C150,67.76 147.124,70 143.582,70L116.418,70C112.876,70 110,67.76 110,65C110,62.24 112.876,60 116.418,60L143.582,60C147.124,60 150,62.24 150,65Z" fill="#00B1FF"/>
          </g>
        </g>
      </g>
    </svg>
  )
}

// ── Icons ─────────────────────────────────────────────────────────────────

const I = {
  overview: <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>,
  requests: <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>,
  analytics:<svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>,
  scanner:  <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>,
  sources:  <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 7v10c0 2 1.5 3 8 3s8-1 8-3V7M4 7c0 2 1.5 3 8 3s8-1 8-3M4 7c0-2 1.5-3 8-3s8 1 8 3M4 12c0 2 1.5 3 8 3s8-1 8-3"/></svg>,
  settings: <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>,
  keys:     <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>,
  users:    <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>,
  integr:   <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"/></svg>,
  depts:    <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>,
  apps:     <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"/></svg>,
  system:   <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/></svg>,
  mail:     <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>,
  chevD:    <svg style={{ width: "14px", height: "14px" }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/></svg>,
  chevR:    <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7"/></svg>,
  chevL:    <svg style={{ width: "20px", height: "20px" }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7"/></svg>,
}

// ── Nav data ──────────────────────────────────────────────────────────────

// `key` resolves to a common.nav.* label via t() (labels cannot be built here
// at module scope -- t is a hook, so NavLink/NavSection resolve them at render).
const NAV_MAIN = [
  { key: "overview",  href: "/",          icon: I.overview,  exact: true  },
  { key: "requests",  href: "/requests",  icon: I.requests,  exact: false },
  { key: "analytics", href: "/analytics", icon: I.analytics, exact: false },
  { key: "sources",   href: "/sources",   icon: I.sources,   exact: false },
  { key: "scanner",   href: "/scanner",   icon: I.scanner,   exact: false },
  { key: "email_delivery", href: "/email-delivery", icon: I.mail, exact: false },
]

const NAV_CONFIG = [
  { key: "settings",       href: "/settings",              icon: I.settings, exact: true  },
  { key: "api_keys",       href: "/settings/keys",         icon: I.keys,     exact: true  },
  { key: "integrations",   href: "/settings/integrations", icon: I.integr,   exact: true  },
  { key: "email_settings", href: "/settings/email",        icon: I.mail,     exact: true  },
]

const NAV_ADMIN = [
  { key: "users",        href: "/users",        icon: I.users,  exact: false },
  { key: "departments",  href: "/departments",  icon: I.depts,  exact: false },
  { key: "applications", href: "/applications", icon: I.apps,   exact: false },
  { key: "system",       href: "/system",       icon: I.system, exact: false },
]

// ── NavLink ───────────────────────────────────────────────────────────────

function NavLink({ item, collapsed, active }: {
  item:      { key: string; href: string; icon: React.ReactNode }
  collapsed: boolean
  active:    boolean
}) {
  const t = useTranslations("common.nav")
  const label = t(item.key)
  return (
    <Link
      href={item.href}
      title={collapsed ? label : undefined}
      style={{
        display:         "flex",
        alignItems:      "center",
        gap:             collapsed ? 0 : "10px",
        padding:         collapsed ? "10px 0" : "7px 14px",
        justifyContent:  collapsed ? "center" : "flex-start",
        borderRadius:    active ? "0" : "0",
        fontSize:        "13px",
        fontWeight:      active ? 500 : 400,
        color:           active ? "#e0d4ff" : "var(--sidebar-text)",
        background:      active ? "var(--sidebar-active-bg)" : "transparent",
        borderLeft:      !collapsed && active ? "3px solid #670FEF" : "3px solid transparent",
        boxShadow:       active ? "inset 0 0 20px rgba(103,15,239,0.08)" : "none",
        transition:      "all 0.15s",
        textDecoration:  "none",
        position:        "relative",
      }}
      onMouseEnter={e => {
        if (!active) (e.currentTarget as HTMLElement).style.background = "var(--sidebar-hover)"
      }}
      onMouseLeave={e => {
        if (!active) (e.currentTarget as HTMLElement).style.background = "transparent"
      }}
    >
      <span style={{ color: active ? "#a78bfa" : "var(--sidebar-text)", flexShrink: 0 }}>
        {item.icon}
      </span>
      {!collapsed && <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{label}</span>}
    </Link>
  )
}

// ── Section ───────────────────────────────────────────────────────────────

function NavSection({ labelKey, sectionKey, items, collapsed, pathname }: {
  labelKey:   string
  sectionKey: string
  items:      { key: string; href: string; icon: React.ReactNode; exact: boolean }[]
  collapsed:  boolean
  pathname:   string
}) {
  const { sectionOpen, toggleSection } = useSidebar()
  const ts = useTranslations("common.nav_section")
  const open = sectionOpen[sectionKey] ?? true

  return (
    <div style={{ paddingTop: "12px" }}>
      {!collapsed ? (
        <button
          onClick={() => toggleSection(sectionKey)}
          style={{
            display:     "flex",
            alignItems:  "center",
            justifyContent: "space-between",
            width:       "100%",
            padding:     "4px 10px",
            marginBottom:"4px",
            background:  "none",
            border:      "none",
            cursor:      "pointer",
            color:       "rgba(255,255,255,0.30)",
          }}
        >
          <span style={{ fontSize: "10px", fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase" }}>
            {ts(labelKey)}
          </span>
          <span style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.2s" }}>
            {I.chevD}
          </span>
        </button>
      ) : (
        <div style={{ margin: "0 8px 8px", borderTop: "1px solid var(--sidebar-border)" }} />
      )}

      <div style={{
        maxHeight:  collapsed ? "none" : (open ? "600px" : "0px"),
        overflow:   "hidden",
        transition: "max-height 220ms ease-in-out",
      }}>
        {items.map((item) => {
          const active = item.exact ? pathname === item.href : pathname.startsWith(item.href)
          return <NavLink key={item.href} item={item} collapsed={collapsed} active={active} />
        })}
      </div>
    </div>
  )
}

// ── Sidebar ───────────────────────────────────────────────────────────────

export function Sidebar() {
  const t = useTranslations("common")
  const pathname = usePathname()
  const { collapsed, toggleCollapsed } = useSidebar()
  const [aboutOpen, setAboutOpen] = useState(false)
  const w = collapsed ? 52 : 228

  return (
    <>
      <aside
        style={{
          position:   "fixed",
          top:        0,
          left:       0,
          height:     "100vh",
          width:      `${w}px`,
          background: "var(--sidebar-bg)",
          backgroundImage: "radial-gradient(ellipse at 80% 0%, rgba(103,15,239,0.18) 0%, transparent 55%), radial-gradient(ellipse at 20% 100%, rgba(0,177,255,0.08) 0%, transparent 50%)",
          borderRight: "1px solid var(--sidebar-border)",
          display:    "flex",
          flexDirection: "column",
          zIndex:     30,
          overflow:   "hidden",
          transition: "width 280ms cubic-bezier(0.4,0,0.2,1)",
        }}
      >
        {/* Header */}
        <div style={{
          display:       "flex",
          alignItems:    "center",
          height:        "56px",
          padding:       collapsed ? "0" : "0 14px",
          borderBottom:  "1px solid var(--sidebar-border)",
          flexShrink:    0,
          gap:           collapsed ? "0" : "10px",
          justifyContent: collapsed ? "center" : "flex-start",
        }}>
          <div style={{ flexShrink: 0 }}>
            <LogoMark size={28} />
          </div>

          <div style={{
            flex:       1,
            overflow:   "hidden",
            display:    collapsed ? "none" : "block",
            transition: "opacity 200ms, max-width 280ms cubic-bezier(0.4,0,0.2,1)",
          }}>
            <p style={{ fontSize: "14px", fontWeight: 600, color: "#ffffff", whiteSpace: "nowrap", lineHeight: 1 }}>
              {t("app_name")}
            </p>
            <p style={{ fontSize: "11px", color: "rgba(255,255,255,0.40)", whiteSpace: "nowrap", marginTop: "2px", lineHeight: 1 }}>
              {t("tagline")}
            </p>
          </div>

          {!collapsed && (
            <button
              onClick={() => toggleCollapsed(true)}
              title={t("sidebar.collapse")}
              style={{
                flexShrink: 0,
                background: "none",
                border:     "none",
                cursor:     "pointer",
                color:      "rgba(255,255,255,0.30)",
                padding:    "4px",
                borderRadius:"4px",
                marginLeft: "auto",
              }}
              onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.70)"}
              onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.30)"}
            >
              {I.chevL}
            </button>
          )}
        </div>

        {/* Expand button */}
        {collapsed && (
          <div style={{ display: "flex", justifyContent: "center", padding: "8px 0" }}>
            <button
              onClick={() => toggleCollapsed(false)}
              title={t("sidebar.expand")}
              style={{
                background: "none", border: "none", cursor: "pointer",
                color: "rgba(255,255,255,0.30)", padding: "4px", borderRadius: "4px",
              }}
              onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.70)"}
              onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.30)"}
            >
              {I.chevR}
            </button>
          </div>
        )}

        {/* Nav */}
        <nav className="no-scrollbar" style={{
          flex:       1,
          overflowY:  "auto",
          overflowX:  "hidden",
          padding:    collapsed ? "8px 0" : "8px 0",
        }}>
          {NAV_MAIN.map(item => {
            const active = item.exact ? pathname === item.href : pathname.startsWith(item.href)
            return <NavLink key={item.href} item={item} collapsed={collapsed} active={active} />
          })}

          <NavSection labelKey="configuration" sectionKey="configuration" items={NAV_CONFIG} collapsed={collapsed} pathname={pathname} />
          <NavSection labelKey="administration" sectionKey="administration" items={NAV_ADMIN} collapsed={collapsed} pathname={pathname} />
        </nav>

        {/* Footer */}
        <div style={{
          padding:    collapsed ? "10px 0" : "10px 14px",
          borderTop:  "1px solid var(--sidebar-border)",
          flexShrink: 0,
          display:    "flex",
          justifyContent: collapsed ? "center" : "flex-start",
        }}>
          <button
            onClick={() => setAboutOpen(true)}
            title={t("sidebar.about")}
            style={{
              background:   "none",
              border:       "none",
              cursor:       "pointer",
              padding:      collapsed ? "6px" : "4px 6px",
              borderRadius: "4px",
              display:      "flex",
              alignItems:   "center",
              gap:          "6px",
            }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.06)"}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = "none"}
          >
            <svg width="14" height="14" fill="none" stroke="rgba(255,255,255,0.3)" strokeWidth={1.75} viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="10"/>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 16v-4M12 8h.01"/>
            </svg>
            {!collapsed && (
              <span style={{ fontSize: "11px", color: "rgba(255,255,255,0.25)" }}>{t("version_footer")}</span>
            )}
          </button>
        </div>
      </aside>

      {/* Spacer */}
      <div style={{ flexShrink: 0, width: `${w}px`, transition: "width 280ms cubic-bezier(0.4,0,0.2,1)" }} />

      {aboutOpen && <AboutModal onClose={() => setAboutOpen(false)} />}
    </>
  )
}
