"use client"

import { useState, useEffect } from "react"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { RequestFilters } from "@/components/requests/RequestFilters"
import { RequestsTable } from "@/components/requests/RequestsTable"
import { Pagination } from "@/components/requests/Pagination"
import { PageSpinner } from "@/components/ui/Spinner"
import { RequestDetailModal } from "@/components/requests/RequestDetail"
import { PAGE_SIZE } from "@/lib/constants"
import { getAuditLogs, exportAuditLogs } from "@/lib/api"

export default function RequestsPage() {
  const [traceId,          setTraceId]          = useState("")
  const [traceIdDebounced, setTraceIdDebounced] = useState("")
  const [decision,         setDecision]         = useState("")
  const [threatCategory,   setThreatCategory]   = useState("")
  const [executionMode,    setExecutionMode]     = useState("")
  const [from,             setFrom]             = useState("")
  const [to,               setTo]               = useState("")
  const [sortBy,           setSortBy]           = useState("created_at")
  const [sortOrder,        setSortOrder]        = useState<"asc" | "desc">("desc")
  const [offset,           setOffset]           = useState(0)
  const [selectedId,       setSelectedId]       = useState<string | null>(null)
  const [exporting,        setExporting]        = useState(false)

  useEffect(() => {
    const t = setTimeout(() => { setTraceIdDebounced(traceId); setOffset(0) }, 400)
    return () => clearTimeout(t)
  }, [traceId])

  const isValidDateRange = !from || !to || from <= to

  const { data, isLoading } = useSWR(
    ["audit-logs", traceIdDebounced, decision, threatCategory, executionMode, from, to, sortBy, sortOrder, offset],
    () => getAuditLogs({
      trace_id:        traceIdDebounced  || undefined,
      decision:        (decision as any) || undefined,
      threat_category: (threatCategory as any) || undefined,
      execution_mode:  (executionMode as any) || undefined,
      from:            from && isValidDateRange ? `${from}T00:00:00` : undefined,
      to:              to   && isValidDateRange ? `${to}T23:59:59`   : undefined,
      sort_by:         sortBy,
      sort_order:      sortOrder,
      limit:           PAGE_SIZE,
      offset,
    }),
    { refreshInterval: 30000 }
  )

  const handleExport = async () => {
    setExporting(true)
    try {
      const blob = await exportAuditLogs({
        decision:        decision       || undefined,
        threat_category: threatCategory || undefined,
        from:            from && isValidDateRange ? `${from}T00:00:00` : undefined,
        to:              to   && isValidDateRange ? `${to}T23:59:59`   : undefined,
      })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement("a")
      a.href     = url
      a.download = `wrapsec_audit_${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error("Export failed", e)
    } finally {
      setExporting(false)
    }
  }

  return (
    <Shell title="Requests">
      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

        {/* Toolbar row — filters left, actions right */}
        <div style={{ display: "flex", alignItems: "flex-start", gap: "12px" }}>

          {/* Filters — takes all available space */}
          <RequestFilters
            traceId={traceId}         decision={decision}
            threatCategory={threatCategory} executionMode={executionMode}
            from={from}               to={to}
            sortBy={sortBy}           sortOrder={sortOrder}
            onTraceId={setTraceId}
            onDecision={v  => { setDecision(v);       setOffset(0) }}
            onThreat={v    => { setThreatCategory(v); setOffset(0) }}
            onExecutionMode={v => { setExecutionMode(v); setOffset(0) }}
            onFrom={v      => { setFrom(v);           setOffset(0) }}
            onTo={v        => { setTo(v);             setOffset(0) }}
            onSortBy={v    => { setSortBy(v);         setOffset(0) }}
            onSortOrder={v => { setSortOrder(v as "asc" | "desc"); setOffset(0) }}
          />

          {/* Actions — fixed right side */}
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
                  Exporting…
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
