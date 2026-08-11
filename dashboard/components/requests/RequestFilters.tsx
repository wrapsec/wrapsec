// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useTranslations } from "next-intl"

function VDivider() {
  return <div style={{ width: 1, height: 20, background: "#e5e7eb", flexShrink: 0 }} />
}

function FilterSelect({ value, onChange, options, width = 140 }: {
  value:    string
  onChange: (v: string) => void
  options:  { value: string; label: string }[]
  width?:   number
}) {
  const active = value !== ""
  return (
    <div style={{ position: "relative", width, flexShrink: 0 }}>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        style={{
          width: "100%", height: "32px",
          padding: "0 24px 0 9px",
          fontSize: "12px", fontFamily: "inherit",
          fontWeight: active ? 600 : 400,
          borderRadius: "6px",
          border: `1px solid ${active ? "rgba(103,15,239,0.35)" : "#e5e7eb"}`,
          background: active ? "rgba(103,15,239,0.06)" : "#fff",
          color: active ? "#670FEF" : "#374151",
          appearance: "none" as const,
          outline: "none", cursor: "pointer",
        }}
      >
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <svg style={{
        position: "absolute", right: 7, top: "50%", transform: "translateY(-50%)",
        pointerEvents: "none", width: 11, height: 11,
        color: active ? "#670FEF" : "#9ca3af",
      }} fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/>
      </svg>
    </div>
  )
}

interface RequestFiltersProps {
  traceId: string; decision: string; threatCategory: string
  executionMode: string; deptId: string; from: string; to: string
  sortBy: string; sortOrder: string
  departments: { id: string; name: string }[]
  onTraceId: (v: string) => void; onDecision: (v: string) => void
  onThreat: (v: string) => void; onExecutionMode: (v: string) => void
  onDeptId: (v: string) => void
  onFrom: (v: string) => void; onTo: (v: string) => void
  onSortBy: (v: string) => void; onSortOrder: (v: string) => void
  // Atomic multi-clears -- one URL update, so they cannot clobber each other.
  onClearDates: () => void; onClearAll: () => void
}

export function RequestFilters({
  traceId, decision, threatCategory, executionMode, deptId, from, to, sortBy, sortOrder,
  departments,
  onTraceId, onDecision, onThreat, onExecutionMode, onDeptId, onFrom, onTo, onSortBy, onSortOrder,
  onClearDates, onClearAll,
}: RequestFiltersProps) {
  const t = useTranslations("pages.requests.filters")
  // Active state lives on the controls themselves (a set control tints violet and
  // shows its value), so there is no separate chip row to make the page jump when
  // a filter clears. Reset a single filter via its own control; "Clear all" resets
  // everything at once.
  const hasFilters   = !!(decision || threatCategory || executionMode || deptId || from || to)
  const hasDateError = !!(from && to && from > to)

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px", flex: 1 }}>
      <div style={{
        display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" as const,
        background: "#fff", border: "1px solid #e5e7eb",
        borderRadius: "8px", padding: "8px 12px",
      }}>

        {/* Search grows to absorb slack: the row fills with no dead space and
            stays a single line on wide screens, wrapping cleanly (left-aligned)
            only when the viewport is genuinely too narrow. */}
        <div style={{ position: "relative", flex: "1 1 200px", minWidth: "180px" }}>
          <svg style={{
            position: "absolute", left: 8, top: "50%", transform: "translateY(-50%)",
            pointerEvents: "none", width: 13, height: 13, color: "#9ca3af",
          }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <input
            type="text" value={traceId}
            onChange={e => onTraceId(e.target.value)}
            placeholder={t("search_trace")}
            style={{
              height: "32px", paddingLeft: "26px", paddingRight: "8px",
              fontSize: "12px", fontFamily: "inherit",
              borderRadius: "6px",
              border: `1px solid ${traceId ? "rgba(103,15,239,0.35)" : "#e5e7eb"}`,
              background: traceId ? "rgba(103,15,239,0.06)" : "#f9fafb",
              color: "#374151", width: "100%", outline: "none",
            }}
          />
        </div>

        <FilterSelect value={decision} onChange={onDecision} width={128}
            options={[
              { value: "", label: t("decision") }, { value: "BLOCK", label: t("block") },
              { value: "SANITIZE", label: t("sanitize") }, { value: "ALLOW", label: t("allow") },
            ]}
          />
          <FilterSelect value={threatCategory} onChange={onThreat} width={148}
            options={[
              { value: "", label: t("threat") },
              { value: "PROMPT_INJECTION",  label: t("prompt_injection")  },
              { value: "JAILBREAK",         label: t("jailbreak")         },
              { value: "MALICIOUS_INTENT",  label: t("malicious_intent")  },
              { value: "DATA_EXFILTRATION", label: t("data_exfiltration") },
              { value: "PII",               label: t("pii")               },
              { value: "TOXICITY",          label: t("toxicity")          },
            ]}
          />
          <FilterSelect value={executionMode} onChange={onExecutionMode} width={110}
            options={[
              { value: "", label: t("mode") },
              { value: "scan_only", label: t("scan_only") },
              { value: "proxy",     label: t("proxy")     },
            ]}
          />
          {departments.length > 0 && (
            <FilterSelect value={deptId} onChange={onDeptId} width={148}
              options={[
                { value: "", label: t("department") },
                ...departments.map(d => ({ value: d.id, label: d.name })),
              ]}
            />
          )}

          <VDivider />

          {/* Sort */}
          <FilterSelect value={sortBy} onChange={onSortBy} width={120}
            options={[
              { value: "created_at", label: t("sort_time")    },
              { value: "risk_score", label: t("sort_risk")    },
              { value: "latency_ms", label: t("sort_latency") },
            ]}
          />
          <button
            onClick={() => onSortOrder(sortOrder === "desc" ? "asc" : "desc")}
            title={sortOrder === "desc" ? t("sort_desc") : t("sort_asc")}
            style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              width: 32, height: 32, borderRadius: "6px", flexShrink: 0,
              border: "1px solid #e5e7eb", background: "#fff",
              cursor: "pointer", color: "#6b7280",
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = "#d1d5db"; (e.currentTarget as HTMLElement).style.background = "#f9fafb" }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = "#e5e7eb"; (e.currentTarget as HTMLElement).style.background = "#fff" }}
          >
            <svg style={{ width: 13, height: 13 }} fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
              {sortOrder === "desc"
                ? <path strokeLinecap="round" strokeLinejoin="round" d="M3 4h13M3 8h9m-9 4h9m5-4v12m0 0l-4-4m4 4l4-4"/>
                : <path strokeLinecap="round" strokeLinejoin="round" d="M3 4h13M3 8h9m-9 4h9m5 0v-12m0 0l-4 4m4-4l4 4"/>
              }
            </svg>
          </button>

          <VDivider />

          {/* Date range */}
          <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
            {(["from", "to"] as const).map((type) => (
              <input
                key={type}
                type="date"
                value={type === "from" ? from : to}
                min={type === "to" ? from || undefined : undefined}
                max={type === "from" ? to || undefined : undefined}
                onChange={e => type === "from" ? onFrom(e.target.value) : onTo(e.target.value)}
                style={{
                  height: "32px", padding: "0 8px",
                  fontSize: "12px", fontFamily: "inherit",
                  borderRadius: "6px",
                  border: `1px solid ${(type === "from" ? from : to) ? "rgba(103,15,239,0.35)" : (hasDateError ? "#fca5a5" : "#e5e7eb")}`,
                  background: (type === "from" ? from : to) ? "rgba(103,15,239,0.06)" : "#fff",
                  color: (type === "from" ? from : to) ? "#670FEF" : "#374151",
                  width: "122px", outline: "none", cursor: "pointer",
                }}
              />
            ))}
            {(from || to) && (
              <button
                onClick={onClearDates}
                style={{
                  display: "flex", alignItems: "center", justifyContent: "center",
                  width: 26, height: 26, borderRadius: "50%",
                  border: "none", background: "#f3f4f6",
                  cursor: "pointer", color: "#6b7280", flexShrink: 0,
                }}
                title={t("clear_dates")}
                onMouseEnter={e => (e.currentTarget.style.background = "#e5e7eb")}
                onMouseLeave={e => (e.currentTarget.style.background = "#f3f4f6")}
              >
                <svg style={{ width: 11, height: 11 }} fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
                </svg>
              </button>
            )}
          </div>

          {/* Clear all */}
          {hasFilters && (
            <>
              <VDivider />
              <button
                onClick={onClearAll}
                style={{
                  fontSize: "11px", fontWeight: 500, color: "#9ca3af",
                  background: "none", border: "none", cursor: "pointer",
                  padding: "4px 6px", borderRadius: "4px", whiteSpace: "nowrap" as const,
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = "#374151"; (e.currentTarget as HTMLElement).style.background = "#f3f4f6" }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = "#9ca3af"; (e.currentTarget as HTMLElement).style.background = "none" }}
              >
                {t("clear_all")}
              </button>
            </>
          )}
      </div>

      {/* Date-range validation only. Rare and self-correcting, so a small line
          under the toolbar is fine and does not cause the routine clear jump. */}
      {hasDateError && (
        <span style={{ fontSize: "11px", color: "#dc2626", display: "flex", alignItems: "center", gap: "4px" }}>
          <svg style={{ width: 12, height: 12 }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
          </svg>
          {t("date_error")}
        </span>
      )}
    </div>
  )
}
