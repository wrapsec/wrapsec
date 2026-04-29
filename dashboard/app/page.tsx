"use client"

import useSWR from "swr"
import { useState } from "react"
import { Shell } from "@/components/layout/Shell"
import { SeverityCard } from "@/components/overview/SeverityCard"
import { MetricCard } from "@/components/overview/MetricCard"
import { OperationalMetrics } from "@/components/overview/OperationalMetrics"
import { TopThreats } from "@/components/overview/TopThreats"
import { RecentRequests } from "@/components/overview/RecentRequests"
import { PageSpinner } from "@/components/ui/Spinner"
import { RequestDetailModal } from "@/components/requests/RequestDetail"
import { getAuditStats, getAuditLogs } from "@/lib/api"
import { POLL_INTERVAL } from "@/lib/constants"

export default function OverviewPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const { data: stats, isLoading: statsLoading } = useSWR(
    "audit-stats",
    () => getAuditStats(),
    { refreshInterval: POLL_INTERVAL }
  )
  const { data: logs, isLoading: logsLoading } = useSWR(
    "recent-requests",
    () => getAuditLogs({ limit: 10, offset: 0 }),
    { refreshInterval: POLL_INTERVAL }
  )

  if ((statsLoading || logsLoading) && !stats) {
    return <Shell title="Overview"><PageSpinner /></Shell>
  }

  const sev = stats?.severity_counts ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }

  return (
    <Shell title="Overview">
      <div style={{ display: "flex", flexDirection: "column", gap: "18px" }}>

        {/* Row 1 — Severity triage (most actionable — leads the page) */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "14px" }}>
          <SeverityCard level="CRITICAL" count={sev.CRITICAL} description="Guardrail overrides" />
          <SeverityCard level="HIGH"     count={sev.HIGH}     description="High-risk blocks" />
          <SeverityCard level="MEDIUM"   count={sev.MEDIUM}   description="Sanitized requests" />
          <SeverityCard level="LOW"      count={sev.LOW}      description="Allowed clean requests" />
        </div>

        {/* Row 2 — Volume breakdown */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "14px" }}>
          <MetricCard
            accent="violet"
            label="Total Requests"
            value={stats?.total_requests.toLocaleString() ?? "—"}
            sub="All time"
          />
          <MetricCard
            accent="none"
            label="Blocked"
            value={stats ? Math.round(stats.block_rate * stats.total_requests).toLocaleString() : "—"}
            sub={stats ? `${(stats.block_rate * 100).toFixed(1)}% of total` : "—"}
            color="red"
          />
          <MetricCard
            accent="none"
            label="Sanitized"
            value={stats ? Math.round(stats.sanitize_rate * stats.total_requests).toLocaleString() : "—"}
            sub={stats ? `${(stats.sanitize_rate * 100).toFixed(1)}% of total` : "—"}
            color="orange"
          />
          <MetricCard
            accent="none"
            label="Allowed"
            value={stats ? Math.round(stats.allow_rate * stats.total_requests).toLocaleString() : "—"}
            sub={stats ? `${(stats.allow_rate * 100).toFixed(1)}% of total` : "—"}
            color="green"
          />
        </div>

        {/* Row 3 — Operational metrics (rates + latency in one compact card) */}
        {stats && <OperationalMetrics stats={stats} />}

        {/* Row 4 — Threat breakdown */}
        {stats && stats.top_threats.length > 0 && (
          <TopThreats threats={stats.top_threats} />
        )}

        {/* Row 5 — Recent requests with severity column */}
        <RecentRequests
          items={logs?.items ?? []}
          onSelect={id => setSelectedId(id)}
        />

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
