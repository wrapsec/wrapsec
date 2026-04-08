"use client"

import { useState } from "react"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card } from "@/components/ui/Card"
import { RequestFilters } from "@/components/requests/RequestFilters"
import { RequestsTable } from "@/components/requests/RequestsTable"
import { Pagination } from "@/components/requests/Pagination"
import { PageSpinner } from "@/components/ui/Spinner"
import { getAuditLogs } from "@/lib/api"
import { PAGE_SIZE, POLL_INTERVAL } from "@/lib/constants"
import { RequestDetailModal } from "@/components/requests/RequestDetail"

export default function RequestsPage() {
  const [decision,       setDecision]       = useState("")
  const [threatCategory, setThreatCategory] = useState("")
  const [offset,         setOffset]         = useState(0)
  const [selectedId,     setSelectedId]     = useState<string | null>(null)

  const { data, isLoading } = useSWR(
    ["audit-logs", decision, threatCategory, offset],
    () => getAuditLogs({
      decision:        decision        || undefined,
      threat_category: threatCategory  || undefined,
      limit:           PAGE_SIZE,
      offset,
    }),
    { refreshInterval: POLL_INTERVAL }
  )

  return (
    <Shell title="Requests">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <RequestFilters
            decision={decision}
            threatCategory={threatCategory}
            onDecision={(v) => { setDecision(v); setOffset(0) }}
            onThreat={(v)   => { setThreatCategory(v); setOffset(0) }}
          />
          {data && (
            <p className="text-xs text-slate-500">
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