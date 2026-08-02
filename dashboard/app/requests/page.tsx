// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState, useEffect, Suspense } from "react"
import { swrKeys } from "@/lib/swrKeys"
import { useSearchParams } from "next/navigation"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { RequestFilters } from "@/components/requests/RequestFilters"
import { RequestsTable } from "@/components/requests/RequestsTable"
import { Pagination } from "@/components/requests/Pagination"
import { PageSpinner } from "@/components/ui/Spinner"
import { RequestDetailModal } from "@/components/requests/RequestDetail"
import { PAGE_SIZE } from "@/lib/constants"
import { VALID_DECISIONS, VALID_THREATS, VALID_EXEC_MODES } from "@/lib/constants"
import { getAuditLogs, exportAuditLogs, getDepartments } from "@/lib/api"

function RequestsPageInner() {
  const searchParams = useSearchParams()

  // URL param sanitisation - validated against constants derived from types.ts.
  // If decision/threat/mode types change, update VALID_* in lib/constants.ts.
  const sanitise     = (val: string | null, allowlist: string[]) =>
    val && allowlist.includes(val) ? val : ""
  // Overview and Analytics deep-link with a full ISO datetime (`useTimeRange`
  // slices ISO to 19 chars). Preserve the timestamp inside state so the API
  // call filters on the exact deep-linked window. The date input widget
  // rejects T-values and is fed `slice(0, 10)` at render time; when the user
  // edits it the widget emits a plain `YYYY-MM-DD` which gets a boundary
  // time reattached in the fetch effect below. Dropping the time in state
  // caused deep-linked 24h windows to widen to ~48h and inflated /requests
  // counts vs the overview badge.
  const sanitiseDate = (val: string | null) => {
    if (!val) return ""
    if (/^\d{4}-\d{2}-\d{2}$/.test(val))                              return val
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(val))             return val
    return ""
  }

  const [traceId,          setTraceId]          = useState("")
  const [traceIdDebounced, setTraceIdDebounced] = useState("")
  const [decision,         setDecision]         = useState(() => sanitise(searchParams.get("decision"), VALID_DECISIONS))
  const [threatCategory,   setThreatCategory]   = useState(() => sanitise(searchParams.get("threat"),   VALID_THREATS))
  const [executionMode,    setExecutionMode]     = useState(() => sanitise(searchParams.get("mode"),     [...VALID_EXEC_MODES]))
  const [from,             setFrom]             = useState(() => sanitiseDate(searchParams.get("from")))
  const [to,               setTo]               = useState(() => sanitiseDate(searchParams.get("to")))
  const [deptId,           setDeptId]           = useState("")
  const [sortBy,           setSortBy]           = useState("created_at")
  const [sortOrder,        setSortOrder]        = useState<"asc" | "desc">("desc")
  const [offset,           setOffset]           = useState(0)
  const [selectedId,       setSelectedId]       = useState<string | null>(null)
  const [exporting,        setExporting]        = useState(false)
  const [exportError,      setExportError]      = useState<string | null>(null)

  useEffect(() => {
    const t = setTimeout(() => { setTraceIdDebounced(traceId); setOffset(0) }, 400)
    return () => clearTimeout(t)
  }, [traceId])

  const isValidDateRange = !from || !to || from <= to

  const { data: deptsData } = useSWR(swrKeys.departments, getDepartments)
  const departments = (deptsData?.departments ?? []).map(d => ({ id: d.id, name: d.name }))

  const { data, isLoading, error: fetchError } = useSWR(
    ["audit-logs", traceIdDebounced, decision, threatCategory, executionMode, deptId, from, to, sortBy, sortOrder, offset],
    () => getAuditLogs({
      trace_id:        traceIdDebounced  || undefined,
      decision:        (decision as any) || undefined,
      threat_category: (threatCategory as any) || undefined,
      execution_mode:  (executionMode as any) || undefined,
      dept_id:         deptId            || undefined,
      from: from && isValidDateRange
        ? (from.includes("T") ? from : `${from}T00:00:00`)
        : undefined,
      to: to && isValidDateRange
        ? (to.includes("T") ? to : `${to}T23:59:59`)
        : undefined,
      sort_by:         sortBy,
      sort_order:      sortOrder,
      limit:           PAGE_SIZE,
      offset,
    }),
    { refreshInterval: 30000 }
  )

  const handleExport = async () => {
    setExporting(true)
    setExportError(null)
    try {
      const blob = await exportAuditLogs({
        decision:        decision       || undefined,
        threat_category: threatCategory || undefined,
        from: from && isValidDateRange
          ? (from.includes("T") ? from : `${from}T00:00:00`)
          : undefined,
        to: to && isValidDateRange
          ? (to.includes("T") ? to : `${to}T23:59:59`)
          : undefined,
      })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement("a")
      a.href     = url
      a.download = `wrapsec_audit_${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e: any) {
      setExportError(e?.message ?? "Export failed. Please try again.")
    } finally {
      setExporting(false)
    }
  }

  return (
    <Shell title="Requests">
      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

        {/* Toolbar row - filters left, actions right */}
        <div style={{ display: "flex", alignItems: "flex-start", gap: "12px" }}>

          {/* Filters - takes all available space */}
          <RequestFilters
            traceId={traceId}         decision={decision}
            threatCategory={threatCategory} executionMode={executionMode}
            deptId={deptId}           departments={departments}
            from={from.slice(0, 10)}  to={to.slice(0, 10)}
            sortBy={sortBy}           sortOrder={sortOrder}
            onTraceId={setTraceId}
            onDecision={v  => { setDecision(v);       setOffset(0) }}
            onThreat={v    => { setThreatCategory(v); setOffset(0) }}
            onExecutionMode={v => { setExecutionMode(v); setOffset(0) }}
            onDeptId={v    => { setDeptId(v);         setOffset(0) }}
            onFrom={v      => { setFrom(v);           setOffset(0) }}
            onTo={v        => { setTo(v);             setOffset(0) }}
            onSortBy={v    => { setSortBy(v);         setOffset(0) }}
            onSortOrder={v => { setSortOrder(v as "asc" | "desc"); setOffset(0) }}
          />

          {/* Actions - fixed right side */}
          <div style={{
            display:        "flex",
            alignItems:     "center",
            gap:            "10px",
            flexShrink:     0,
            paddingTop:     "4px",
          }}>
            {/* Result count */}
            {data && (
              <div style={{
                display:      "flex",
                alignItems:   "center",
                gap:          "6px",
                padding:      "6px 12px",
                borderRadius: "6px",
                background:   "#f9fafb",
                border:       "1px solid #e5e7eb",
              }}>
                <svg style={{ width: 13, height: 13, color: "#9ca3af" }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
                </svg>
                <span style={{ fontSize: "12px", fontWeight: 600, color: "#374151", fontVariantNumeric: "tabular-nums" }}>
                  {data.total.toLocaleString()}
                </span>
                <span style={{ fontSize: "11px", color: "#9ca3af" }}>requests</span>
              </div>
            )}

            {/* Export error */}
            {exportError && (
              <span style={{ fontSize: "11px", color: "#dc2626", maxWidth: 180 }}>
                {exportError}
              </span>
            )}

            {/* Export button */}
            <button
              onClick={handleExport}
              disabled={exporting}
              style={{
                display:      "inline-flex",
                alignItems:   "center",
                gap:          "6px",
                padding:      "6px 14px",
                fontSize:     "12px",
                fontWeight:   500,
                fontFamily:   "inherit",
                borderRadius: "6px",
                border:       "1px solid var(--ws-violet, #670FEF)",
                background:   "transparent",
                color:        "var(--ws-violet, #670FEF)",
                cursor:       exporting ? "not-allowed" : "pointer",
                opacity:      exporting ? 0.6 : 1,
                transition:   "all 0.15s",
                whiteSpace:   "nowrap" as const,
                height:       "32px",
              }}
              onMouseEnter={e => {
                if (!exporting) {
                  (e.currentTarget as HTMLElement).style.background = "rgba(103,15,239,0.06)"
                }
              }}
              onMouseLeave={e => {
                (e.currentTarget as HTMLElement).style.background = "transparent"
              }}
            >
              {exporting ? (
                <>
                  <svg style={{ width: 13, height: 13, animation: "spin 1s linear infinite" }} fill="none" viewBox="0 0 24 24">
                    <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
                    <circle style={{ opacity: 0.25 }} cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path style={{ opacity: 0.75 }} fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                  </svg>
                  Exporting
                </>
              ) : (
                <>
                  <svg style={{ width: 13, height: 13 }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                  </svg>
                  Export CSV
                </>
              )}
            </button>
          </div>
        </div>

        {/* Table */}
        <div style={{
          background:   "#fff",
          border:       "1px solid #e5e7eb",
          borderRadius: "8px",
          overflow:     "hidden",
        }}>
          {isLoading && !data ? (
            <PageSpinner />
          ) : fetchError ? (
            <div style={{ padding: "48px 24px", textAlign: "center" }}>
              <p style={{ fontSize: "13px", fontWeight: 600, color: "#374151", marginBottom: "4px" }}>
                Failed to load requests
              </p>
              <p style={{ fontSize: "12px", color: "#9ca3af" }}>
                {fetchError?.message ?? "Unable to reach the API. Check your connection and try again."}
              </p>
            </div>
          ) : (
            <>
              <RequestsTable
                items={data?.items ?? []}
                onSelect={id => setSelectedId(id)}
              />
              <Pagination
                total={data?.total ?? 0}
                offset={offset}
                limit={PAGE_SIZE}
                onChange={setOffset}
              />
            </>
          )}
        </div>

      </div>

      {selectedId && (
        <RequestDetailModal
          traceId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </Shell>
  )
}


export default function RequestsPage() {
  return <Suspense><RequestsPageInner /></Suspense>
}

