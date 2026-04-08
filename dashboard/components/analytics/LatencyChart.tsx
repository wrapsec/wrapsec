"use client"

import { Card, CardHeader } from "@/components/ui/Card"
import { AuditStatsResponse } from "@/lib/types"
import { formatLatency } from "@/lib/utils"

export function LatencyStats({ stats }: { stats: AuditStatsResponse }) {
  const items = [
    { label: "Average latency",      value: formatLatency(stats.avg_latency_ms), color: "bg-blue-800" },
    { label: "P95 latency",          value: formatLatency(stats.p95_latency_ms), color: "bg-orange-500" },
  ]

  const max = Math.max(stats.avg_latency_ms, stats.p95_latency_ms) || 1

  return (
    <Card>
      <CardHeader
        title="Latency Overview"
        subtitle="Processing time across all requests"
      />
      <div className="space-y-4">
        {items.map((item) => (
          <div key={item.label}>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs text-slate-600">{item.label}</span>
              <span className="text-xs font-semibold text-slate-900">{item.value}</span>
            </div>
            <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
              <div
                className={`h-full ${item.color} rounded-full`}
                style={{
                  width: `${(item.label === "Average latency"
                    ? stats.avg_latency_ms
                    : stats.p95_latency_ms) / max * 100}%`
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}