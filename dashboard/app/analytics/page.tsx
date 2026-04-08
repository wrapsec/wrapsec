"use client"

import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { StatsCards } from "@/components/analytics/StatsCards"
import { ThreatChart } from "@/components/analytics/ThreatChart"
import { LatencyStats } from "@/components/analytics/LatencyChart"
import { PageSpinner } from "@/components/ui/Spinner"
import { getAuditStats } from "@/lib/api"
import { POLL_INTERVAL } from "@/lib/constants"

export default function AnalyticsPage() {
  const { data: stats, isLoading } = useSWR(
    "analytics-stats",
    getAuditStats,
    { refreshInterval: POLL_INTERVAL }
  )

  return (
    <Shell title="Analytics">
      {isLoading || !stats ? (
        <PageSpinner />
      ) : (
        <div className="space-y-5">
          <StatsCards stats={stats} />
          <div className="grid grid-cols-2 gap-4">
            <ThreatChart threats={stats.top_threats} />
            <LatencyStats stats={stats} />
          </div>
        </div>
      )}
    </Shell>
  )
}