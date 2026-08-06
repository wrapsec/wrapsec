// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"

/**
 * A tab is declared by config, not by layout: a future module (MCP tool calls,
 * RAG chunk provenance, agent timeline) adds a `TabDef` to the array without
 * touching the container. `visible: false` hides a tab (e.g. Proxy on a
 * scan-only request) while keeping the config declarative.
 */
export interface TabDef {
  id:       string
  label:    string
  render:   () => React.ReactNode
  visible?: boolean
}

/**
 * Uncontrolled by default (owns its active tab); pass `activeId` + `onChange`
 * to control it (e.g. a "View Raw Request" action that jumps to the Raw tab).
 */
export function Tabs({ tabs, activeId, onChange, initialId }: {
  tabs:       TabDef[]
  activeId?:  string
  onChange?:  (id: string) => void
  initialId?: string
}) {
  const visible = tabs.filter(t => t.visible !== false)
  const [internal, setInternal] = useState(initialId ?? visible[0]?.id)
  const active = activeId ?? internal
  const current = visible.find(t => t.id === active) ?? visible[0]

  function select(id: string) {
    onChange?.(id)
    if (activeId === undefined) setInternal(id)
  }

  return (
    <div>
      <div className="flex gap-1 border-b border-slate-100 px-4 sticky top-0 bg-white z-10" role="tablist">
        {visible.map(t => (
          <button
            key={t.id}
            role="tab"
            aria-selected={t.id === current?.id}
            onClick={() => select(t.id)}
            className={`px-3 py-2.5 text-xs font-medium border-b-2 -mb-px whitespace-nowrap transition-colors ${
              t.id === current?.id
                ? "border-[#670FEF] text-[#670FEF]"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="px-5 py-5" role="tabpanel">{current?.render()}</div>
    </div>
  )
}
