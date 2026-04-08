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
import { getAuditLogs } from "@/lib/api"
import { PAGE_SIZE, POLL_INTERVAL } from "@/lib/constants"

export default function RequestsPage() {
  const [traceId,        setTraceId]        = useState("")
  const [traceIdDebounced, setTraceIdDebounced] = useState("")
  const [decision,       setDecision]       = useState("")
  const [threatCategory, setThreatCategory] = useState("")
  const [from,           setFrom]           = useState("")
  const [to,             setTo]             = useState("")
  const [sortBy,         setSortBy]         = useState("created_at")
  const [sortOrder,      setSortOrder]      = useState<"asc" | "desc">("desc")
  const [offset,         setOffset]         = useState(0)
  const [selectedId,     setSelectedId]     = useState<string | null>(null)

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
      decision:        decision          || undefined,
      threat_category: threatCategory    || undefined,
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
            <p className="text-xs text-slate-500 mt-7">
              {data.total.toLocaleString()} total requests
            </p>
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