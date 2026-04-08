"use client"

import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { MetricCard } from "@/components/overview/MetricCard"
import { DecisionChart } from "@/components/overview/DecisionChart"
import { TopThreats } from "@/components/overview/TopThreats"
import { RecentRequests } from "@/components/overview/RecentRequests"
import { PageSpinner } from "@/components/ui/Spinner"
import { getAuditStats, getAuditLogs } from "@/lib/api"
import { formatRate, formatLatency } from "@/lib/utils"
import { POLL_INTERVAL } from "@/lib/constants"
import { useState } from "react"
import { RequestDetailModal } from "@/components/requests/RequestDetail"

export default function OverviewPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const { data: stats, isLoading: statsLoading } = useSWR(
    "audit-stats",
    getAuditStats,
    { refreshInterval: POLL_INTERVAL }
  )

  const { data: logs, isLoading: logsLoading } = useSWR(
    "recent-requests",
    () => getAuditLogs({ limit: 10, offset: 0 }),
    { refreshInterval: POLL_INTERVAL }
  )

  const loading = statsLoading || logsLoading

  return (
    <Shell title="Overview">
      {loading && !stats ? (
        <PageSpinner />
      ) : (
        <div className="space-y-5">
          {/* Metric cards */}
          <div className="grid grid-cols-4 gap-4">
            <MetricCard
              label="Total Requests"
              value={stats?.total_requests.toLocaleString() ?? "—"}
              sub="All time"
            />
            <MetricCard
              label="Blocked"
              value={stats ? formatRate(stats.block_rate) : "—"}
              sub={`${Math.round((stats?.block_rate ?? 0) * (stats?.total_requests ?? 0))} requests`}
              color="red"
            />
            <MetricCard
              label="Sanitized"
              value={stats ? formatRate(stats.sanitize_rate) : "—"}
              sub={`${Math.round((stats?.sanitize_rate ?? 0) * (stats?.total_requests ?? 0))} requests`}
              color="orange"
            />
            <MetricCard
              label="Allowed"
              value={stats ? formatRate(stats.allow_rate) : "—"}
              sub={`${Math.round((stats?.allow_rate ?? 0) * (stats?.total_requests ?? 0))} requests`}
              color="green"
            />
          </div>

          {/* Latency cards */}
          <div className="grid grid-cols-2 gap-4">
            <MetricCard
              label="Avg Latency"
              value={stats ? formatLatency(stats.avg_latency_ms) : "—"}
              sub="Mean processing time"
            />
            <MetricCard
              label="P95 Latency"
              value={stats ? formatLatency(stats.p95_latency_ms) : "—"}
              sub="95th percentile"
            />
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-2 gap-4">
            {stats && (
              <DecisionChart
                blockRate={stats.block_rate}
                sanitizeRate={stats.sanitize_rate}
                allowRate={stats.allow_rate}
                total={stats.total_requests}
              />
            )}
            {stats && (
              <TopThreats threats={stats.top_threats} />
            )}
          </div>

          {/* Recent requests */}
          <RecentRequests
            items={logs?.items ?? []}
            onSelect={(id) => setSelectedId(id)}
          />
        </div>
      )}
      {selectedId && (
        <RequestDetailModal
          traceId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </Shell>
  )
}