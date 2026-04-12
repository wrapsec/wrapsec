"use client"

import { useState, useEffect } from "react"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card } from "@/components/ui/Card"
import { RequestFilters } from "@/components/requests/RequestFilters"
import { RequestsTable } from "@/components/requests/RequestsTable"
import { Pagination } from "@/components/requests/Pagination"
import { PageSpinner } from "@/components/ui/Spinner"
import { RequestDetailModal } from "@/components/requests/RequestDetail"
import { PAGE_SIZE, POLL_INTERVAL } from "@/lib/constants"
import { getAuditLogs, exportAuditLogs } from "@/lib/api"

export default function RequestsPage() {
  const [traceId,           setTraceId]           = useState("")
  const [traceIdDebounced,  setTraceIdDebounced]  = useState("")
  const [decision,          setDecision]          = useState("")
  const [threatCategory,    setThreatCategory]    = useState("")
  const [from,              setFrom]              = useState("")
  const [to,                setTo]                = useState("")
  const [sortBy,            setSortBy]            = useState("created_at")
  const [sortOrder,         setSortOrder]         = useState<"asc" | "desc">("desc")
  const [offset,            setOffset]            = useState(0)
  const [selectedId,        setSelectedId]        = useState<string | null>(null)

  // Debounce trace ID search — wait 400ms after user stops typing
  useEffect(() => {
    const timer = setTimeout(() => {
      setTraceIdDebounced(traceId)
      setOffset(0)
    }, 400)
    return () => clearTimeout(timer)
  }, [traceId])

  const isValidDateRange = !from || !to || from <= to

  const { data, isLoading } = useSWR(
    ["audit-logs", traceIdDebounced, decision, threatCategory, from, to, sortBy, sortOrder, offset],
    () => getAuditLogs({
      trace_id:        traceIdDebounced  || undefined,
      decision:        (decision as any) || undefined,
      threat_category: (threatCategory as any) || undefined,
      from:            from && isValidDateRange ? `${from}T00:00:00` : undefined,
      to:              to   && isValidDateRange ? `${to}T23:59:59`   : undefined,
      sort_by:         sortBy,
      sort_order:      sortOrder,
      limit:           PAGE_SIZE,
      offset,
    }),
    { refreshInterval: POLL_INTERVAL }
  )

  return (
    <Shell title="Requests">
      <div className="space-y-4">
        <div className="flex items-start justify-between">
          <RequestFilters
            traceId={traceId}
            decision={decision}
            threatCategory={threatCategory}
            from={from}
            to={to}
            sortBy={sortBy}
            sortOrder={sortOrder}
            onTraceId={(v)   => setTraceId(v)}
            onDecision={(v)  => { setDecision(v);       setOffset(0) }}
            onThreat={(v)    => { setThreatCategory(v); setOffset(0) }}
            onFrom={(v)      => { setFrom(v);           setOffset(0) }}
            onTo={(v)        => { setTo(v);             setOffset(0) }}
            onSortBy={(v)    => { setSortBy(v);         setOffset(0) }}
            onSortOrder={(v) => { setSortOrder(v as "asc" | "desc"); setOffset(0) }}
          />
          {data && (
            <div className="flex items-center gap-3 mt-7">
              <p className="text-xs text-slate-500">
                {data.total.toLocaleString()} total requests
              </p>
              <ExportButton
                decision={decision}
                threatCategory={threatCategory}
                from={from}
                to={to}
                isValidDateRange={isValidDateRange}
              />
            </div>
          )}
        </div>

        <Card padding={false}>
          {isLoading && !data ? (
            <PageSpinner />
          ) : (
            <>
              <RequestsTable
                items={data?.items ?? []}
                onSelect={(id) => setSelectedId(id)}
              />
              <Pagination
                total={data?.total ?? 0}
                offset={offset}
                limit={PAGE_SIZE}
                onChange={setOffset}
              />
            </>
          )}
        </Card>
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

// ── Export CSV Button ──────────────────────────────────────────────────────

function ExportButton({
  decision,
  threatCategory,
  from,
  to,
  isValidDateRange,
}: {
  decision:         string
  threatCategory:   string
  from:             string
  to:               string
  isValidDateRange: boolean
}) {
  const [exporting, setExporting] = useState(false)

  const handleExport = async () => {
    setExporting(true)
    try {
      const blob = await exportAuditLogs({
        decision:        decision        || undefined,
        threat_category: threatCategory  || undefined,
        from:            from && isValidDateRange ? `${from}T00:00:00` : undefined,
        to:              to   && isValidDateRange ? `${to}T23:59:59`   : undefined,
      })
      const url      = URL.createObjectURL(blob)
      const a        = document.createElement("a")
      a.href         = url
      a.download     = `wrapsec_audit_${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error("Export failed", e)
    } finally {
      setExporting(false)
    }
  }

  return (
    <button
      onClick={handleExport}
      disabled={exporting}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-600 bg-white border border-slate-200 rounded-md hover:bg-slate-50 hover:text-slate-900 disabled:opacity-50 transition-colors"
    >
      {exporting ? (
        <>
          <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Exporting...
        </>
      ) : (
        <>
          <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          Export CSV
        </>
      )}
    </button>
  )
}
